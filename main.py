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
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
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

# Add these imports to main.py and include these additional endpoints

# Expense endpoints
@app.post("/api/groups/{group_id}/expenses", response_model=schemas.ExpenseResponse)
def create_expense(
    group_id: int,
    expense: schemas.ExpenseCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify membership
    membership = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == current_user.id
    ).first()
    
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    # Validate splits sum equals amount
    total_split = sum(split.amount for split in expense.splits)
    if abs(total_split - expense.amount) > 0.01:
        raise HTTPException(status_code=400, detail="Split amounts must sum to total expense amount")
    
    # Create expense
    new_expense = models.Expense(
        group_id=group_id,
        description=expense.description,
        amount=expense.amount,
        creator_id=current_user.id,
        payer_id=expense.payer_id,
        expense_date=expense.expense_date,
        is_recurring=expense.is_recurring,
        recurring_interval=expense.recurring_interval,
        recurring_end_date=expense.recurring_end_date
    )
    db.add(new_expense)
    db.flush()
    
    # Create splits
    for split in expense.splits:
        expense_split = models.ExpenseSplit(
            expense_id=new_expense.id,
            user_id=split.user_id,
            amount=split.amount
        )
        db.add(expense_split)
    
    # Update balances
    update_balances_for_expense(db, new_expense, expense.splits)
    
    # Create audit log
    audit_log = models.AuditLog(
        group_id=group_id,
        user_id=current_user.id,
        action=models.ActionType.CREATE,
        entity_type="expense",
        entity_id=new_expense.id,
        details=f"Created expense: {expense.description} for ${expense.amount}"
    )
    db.add(audit_log)
    
    db.commit()
    db.refresh(new_expense)
    return new_expense

@app.get("/api/groups/{group_id}/expenses", response_model=List[schemas.ExpenseResponse])
def get_expenses(
    group_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    membership = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == current_user.id
    ).first()
    
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    expenses = db.query(models.Expense).filter(models.Expense.group_id == group_id).all()
    return expenses

@app.get("/api/groups/{group_id}/expenses/{expense_id}", response_model=schemas.ExpenseResponse)
def get_expense(
    group_id: int,
    expense_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    membership = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == current_user.id
    ).first()
    
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    expense = db.query(models.Expense).filter(
        models.Expense.id == expense_id,
        models.Expense.group_id == group_id
    ).first()
    
    if not expense:
        raise HTTPException(status_code=404, detail="Expense not found")
    
    return expense

@app.put("/api/groups/{group_id}/expenses/{expense_id}", response_model=schemas.ExpenseResponse)
def update_expense(
    group_id: int,
    expense_id: int,
    expense_update: schemas.ExpenseUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    expense = db.query(models.Expense).filter(
        models.Expense.id == expense_id,
        models.Expense.group_id == group_id
    ).first()
    
    if not expense:
        raise HTTPException(status_code=404, detail="Expense not found")
    
    # Check permissions: creator can update their own expenses, admin can update any
    if expense.creator_id != current_user.id and group.admin_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this expense")
    
    # Revert old balances
    revert_balances_for_expense(db, expense)
    
    # Update expense fields
    if expense_update.description:
        expense.description = expense_update.description
    if expense_update.amount:
        expense.amount = expense_update.amount
    if expense_update.payer_id:
        expense.payer_id = expense_update.payer_id
    if expense_update.expense_date:
        expense.expense_date = expense_update.expense_date
    if expense_update.is_recurring is not None:
        expense.is_recurring = expense_update.is_recurring
    if expense_update.recurring_interval:
        expense.recurring_interval = expense_update.recurring_interval
    if expense_update.recurring_end_date:
        expense.recurring_end_date = expense_update.recurring_end_date
    
    # Update splits if provided
    if expense_update.splits:
        # Validate splits
        total_split = sum(split.amount for split in expense_update.splits)
        if abs(total_split - expense.amount) > 0.01:
            raise HTTPException(status_code=400, detail="Split amounts must sum to total expense amount")
        
        # Delete old splits
        db.query(models.ExpenseSplit).filter(models.ExpenseSplit.expense_id == expense_id).delete()
        
        # Create new splits
        for split in expense_update.splits:
            expense_split = models.ExpenseSplit(
                expense_id=expense_id,
                user_id=split.user_id,
                amount=split.amount
            )
            db.add(expense_split)
        
        db.flush()
    
    # Recalculate balances
    splits = db.query(models.ExpenseSplit).filter(models.ExpenseSplit.expense_id == expense_id).all()
    update_balances_for_expense(db, expense, splits)
    
    # Create audit log
    audit_log = models.AuditLog(
        group_id=group_id,
        user_id=current_user.id,
        action=models.ActionType.UPDATE,
        entity_type="expense",
        entity_id=expense_id,
        details=f"Updated expense: {expense.description}"
    )
    db.add(audit_log)
    
    db.commit()
    db.refresh(expense)
    return expense

@app.delete("/api/groups/{group_id}/expenses/{expense_id}")
def delete_expense(
    group_id: int,
    expense_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    expense = db.query(models.Expense).filter(
        models.Expense.id == expense_id,
        models.Expense.group_id == group_id
    ).first()
    
    if not expense:
        raise HTTPException(status_code=404, detail="Expense not found")
    
    # Check permissions
    if expense.creator_id != current_user.id and group.admin_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this expense")
    
    # Revert balances
    revert_balances_for_expense(db, expense)
    
    # Create audit log before deletion
    audit_log = models.AuditLog(
        group_id=group_id,
        user_id=current_user.id,
        action=models.ActionType.DELETE,
        entity_type="expense",
        entity_id=expense_id,
        details=f"Deleted expense: {expense.description} for ${expense.amount}"
    )
    db.add(audit_log)
    
    db.delete(expense)
    db.commit()
    
    return {"message": "Expense deleted successfully"}

# Balance endpoints
@app.get("/api/groups/{group_id}/balances", response_model=List[schemas.BalanceResponse])
def get_balances(
    group_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    membership = db.query(models.GroupMembership).filter(
        models.GroupMembership.group_id == group_id,
        models.GroupMembership.user_id == current_user.id
    ).first()
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this group")

    balances = db.query(models.Balance).filter(models.Balance.group_id == group_id).all()

    # Minimal: fetch users once, build the objects your schema requires
    user_ids = [b.user_id for b in balances] or [0]
    users = {u.id: u for u in db.query(models.User).filter(models.User.id.in_(user_ids)).all()}

    result = []
    for b in balances:
        u = users.get(b.user_id)
        # If somehow no user found, you can choose to skip/raise. We'll include a minimal stub.
        user_payload = {
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "created_at": (u.created_at.isoformat().replace("+00:00", "Z")
                           if hasattr(u.created_at, "isoformat") else str(u.created_at)),
        } if u else {
            "id": b.user_id, "email": "", "name": "", "created_at": ""
        }
        result.append({
            "user_id": b.user_id,
            "balance": float(getattr(b, "balance", 0) or 0),  # handle Decimal/None
            "user": user_payload,
        })
    return result

# Audit log endpoints
@app.get("/api/groups/{group_id}/audit", response_model=List[schemas.AuditLogResponse])
def get_audit_logs(
    group_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    if group.admin_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only group admin can view audit logs")
    
    audit_logs = db.query(models.AuditLog).filter(
        models.AuditLog.group_id == group_id
    ).order_by(models.AuditLog.timestamp.desc()).all()
    
    return audit_logs

# Helper functions for balance calculation
def update_balances_for_expense(db: Session, expense: models.Expense, splits):
    """Update balances when an expense is created or updated"""
    # Payer gets positive balance (they paid)
    payer_balance = db.query(models.Balance).filter(
        models.Balance.group_id == expense.group_id,
        models.Balance.user_id == expense.payer_id
    ).first()
    
    if not payer_balance:
        payer_balance = models.Balance(
            group_id=expense.group_id,
            user_id=expense.payer_id,
            balance=0.0
        )
        db.add(payer_balance)
    
    payer_balance.balance += expense.amount
    
    # Each split participant gets negative balance (they owe)
    for split in splits:
        user_balance = db.query(models.Balance).filter(
            models.Balance.group_id == expense.group_id,
            models.Balance.user_id == split.user_id
        ).first()
        
        if not user_balance:
            user_balance = models.Balance(
                group_id=expense.group_id,
                user_id=split.user_id,
                balance=0.0
            )
            db.add(user_balance)
        
        user_balance.balance -= split.amount

def revert_balances_for_expense(db: Session, expense: models.Expense):
    """Revert balances when an expense is deleted or before update"""
    # Revert payer balance
    payer_balance = db.query(models.Balance).filter(
        models.Balance.group_id == expense.group_id,
        models.Balance.user_id == expense.payer_id
    ).first()
    
    if payer_balance:
        payer_balance.balance -= expense.amount
    
    # Revert split balances
    splits = db.query(models.ExpenseSplit).filter(models.ExpenseSplit.expense_id == expense.id).all()
    for split in splits:
        user_balance = db.query(models.Balance).filter(
            models.Balance.group_id == expense.group_id,
            models.Balance.user_id == split.user_id
        ).first()
        
        if user_balance:
            user_balance.balance += split.amount
