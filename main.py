from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List, Optional
import jwt
from passlib.context import CryptContext

from database import get_db, engine
import models
import schemas

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Expense Management API", version="1.0.0")

# Security setup
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Authentication endpoints
@app.post("/api/auth/signup", response_model=schemas.UserResponse)
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pwd = hash_password(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_pwd, name=user.name)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/api/auth/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/logout")
def logout(current_user: models.User = Depends(get_current_user)):
    return {"message": "Successfully logged out"}

# Group endpoints
@app.post("/api/groups", response_model=schemas.GroupResponse)
def create_group(group: schemas.GroupCreate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_group = models.Group(name=group.name, description=group.description, admin_id=current_user.id)
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    
    # Add creator as member
    membership = models.GroupMembership(user_id=current_user.id, group_id=new_group.id)
    db.add(membership)
    db.commit()
    
    return new_group

@app.get("/api/groups", response_model=List[schemas.GroupResponse])
def get_groups(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    memberships = db.query(models.GroupMembership).filter(models.GroupMembership.user_id == current_user.id).all()
    groups = [membership.group for membership in memberships]
    return groups

@app.get("/api/groups/{group_id}", response_model=schemas.GroupResponse)
def get_group(group_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    membership = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == current_user.id
    ).first()
    
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    return membership.group

@app.put("/api/groups/{group_id}", response_model=schemas.GroupResponse)
def update_group(group_id: int, group_update: schemas.GroupUpdate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    if group.admin_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only group admin can update group")
    
    if group_update.name:
        group.name = group_update.name
    if group_update.description:
        group.description = group_update.description
    
    db.commit()
    db.refresh(group)
    return group

@app.delete("/api/groups/{group_id}")
def delete_group(group_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    if group.admin_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only group admin can delete group")
    
    db.delete(group)
    db.commit()
    return {"message": "Group deleted successfully"}

# Group membership endpoints
@app.post("/api/groups/{group_id}/members")
def add_member(group_id: int, member: schemas.MemberAdd, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    is_member = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == current_user.id
    ).first()
    
    if not is_member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    user_to_add = db.query(models.User).filter(models.User.email == member.email).first()
    if not user_to_add:
        raise HTTPException(status_code=404, detail="User not found")
    
    existing_membership = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == user_to_add.id
    ).first()
    
    if existing_membership:
        raise HTTPException(status_code=400, detail="User already a member")
    
    new_membership = models.GroupMembership(user_id=user_to_add.id, group_id=group_id)
    db.add(new_membership)
    db.commit()
    
    return {"message": f"User {member.email} added to group"}

@app.get("/api/groups/{group_id}/members", response_model=List[schemas.UserResponse])
def get_members(group_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    is_member = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == current_user.id
    ).first()
    
    if not is_member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    memberships = db.query(models.GroupMembership).filter(models.GroupMembership.group_id == group_id).all()
    members = [membership.user for membership in memberships]
    return members

@app.delete("/api/groups/{group_id}/members/{user_id}")
def remove_member(group_id: int, user_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    if group.admin_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only group admin can remove members")
    
    membership = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == user_id
    ).first()
    
    if not membership:
        raise HTTPException(status_code=404, detail="Member not found in group")
    
    db.delete(membership)
    db.commit()
    
    return {"message": "Member removed successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
