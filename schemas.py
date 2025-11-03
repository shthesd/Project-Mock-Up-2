from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List
from datetime import datetime

# User schemas
class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    created_at: datetime
    
    class Config:
        from_attributes = True

# Group schemas
class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None

class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class GroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    admin_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# Member schemas
class MemberAdd(BaseModel):
    email: EmailStr

class MemberResponse(BaseModel):
    user: UserResponse
    joined_at: datetime
    
    class Config:
        from_attributes = True

# Expense split schema
class ExpenseSplitCreate(BaseModel):
    user_id: int
    amount: float = Field(gt=0)

class ExpenseSplitResponse(BaseModel):
    id: int
    user_id: int
    amount: float
    
    class Config:
        from_attributes = True

# Expense schemas
class ExpenseCreate(BaseModel):
    description: str
    amount: float = Field(gt=0)
    payer_id: int
    expense_date: datetime
    splits: List[ExpenseSplitCreate]
    is_recurring: bool = False
    recurring_interval: Optional[str] = None  # daily, weekly, monthly, yearly
    recurring_end_date: Optional[datetime] = None

class ExpenseUpdate(BaseModel):
    description: Optional[str] = None
    amount: Optional[float] = Field(None, gt=0)
    payer_id: Optional[int] = None
    expense_date: Optional[datetime] = None
    splits: Optional[List[ExpenseSplitCreate]] = None
    is_recurring: Optional[bool] = None
    recurring_interval: Optional[str] = None
    recurring_end_date: Optional[datetime] = None

class ExpenseResponse(BaseModel):
    id: int
    group_id: int
    description: str
    amount: float
    creator_id: int
    payer_id: int
    expense_date: datetime
    created_at: datetime
    is_recurring: bool
    recurring_interval: Optional[str]
    recurring_end_date: Optional[datetime]
    splits: List[ExpenseSplitResponse]
    
    class Config:
        from_attributes = True

# Balance schemas
class BalanceResponse(BaseModel):
    user_id: int
    balance: float
    user: UserResponse
    
    class Config:
        from_attributes = True

# Payment schemas
class PaymentCreate(BaseModel):
    payee_id: int
    amount: float = Field(gt=0)
    notes: Optional[str] = None

class PaymentResponse(BaseModel):
    id: int
    group_id: int
    payer_id: int
    payee_id: int
    amount: float
    payment_date: datetime
    notes: Optional[str]
    
    class Config:
        from_attributes = True

# Audit log schemas
class AuditLogResponse(BaseModel):
    id: int
    user_id: int
    action: str
    entity_type: str
    entity_id: Optional[int]
    details: Optional[str]
    timestamp: datetime
    
    class Config:
        from_attributes = True
