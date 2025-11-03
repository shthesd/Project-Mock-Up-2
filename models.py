from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Text, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import enum

class ActionType(enum.Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    ADD_MEMBER = "add_member"
    REMOVE_MEMBER = "remove_member"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    admin_groups = relationship("Group", back_populates="admin", foreign_keys="Group.admin_id")
    memberships = relationship("GroupMembership", back_populates="user", cascade="all, delete-orphan")
    expenses_created = relationship("Expense", back_populates="creator", foreign_keys="Expense.creator_id")
    expenses_paid = relationship("Expense", back_populates="payer", foreign_keys="Expense.payer_id")
    expense_splits = relationship("ExpenseSplit", back_populates="user")
    payments_from = relationship("Payment", back_populates="payer", foreign_keys="Payment.payer_id")
    payments_to = relationship("Payment", back_populates="payee", foreign_keys="Payment.payee_id")

class Group(Base):
    __tablename__ = "groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    admin = relationship("User", back_populates="admin_groups", foreign_keys=[admin_id])
    memberships = relationship("GroupMembership", back_populates="group", cascade="all, delete-orphan")
    expenses = relationship("Expense", back_populates="group", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="group", cascade="all, delete-orphan")
    balances = relationship("Balance", back_populates="group", cascade="all, delete-orphan")

class GroupMembership(Base):
    __tablename__ = "group_memberships"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    joined_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="memberships")
    group = relationship("Group", back_populates="memberships")

class Expense(Base):
    __tablename__ = "expenses"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    description = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    creator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    payer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expense_date = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_recurring = Column(Boolean, default=False)
    recurring_interval = Column(String)  # daily, weekly, monthly, yearly
    recurring_end_date = Column(DateTime(timezone=True))
    
    # Relationships
    group = relationship("Group", back_populates="expenses")
    creator = relationship("User", back_populates="expenses_created", foreign_keys=[creator_id])
    payer = relationship("User", back_populates="expenses_paid", foreign_keys=[payer_id])
    splits = relationship("ExpenseSplit", back_populates="expense", cascade="all, delete-orphan")

class ExpenseSplit(Base):
    __tablename__ = "expense_splits"
    
    id = Column(Integer, primary_key=True, index=True)
    expense_id = Column(Integer, ForeignKey("expenses.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    
    # Relationships
    expense = relationship("Expense", back_populates="splits")
    user = relationship("User", back_populates="expense_splits")

class Payment(Base):
    __tablename__ = "payments"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    payer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    payee_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    payment_date = Column(DateTime(timezone=True), server_default=func.now())
    notes = Column(String)
    
    # Relationships
    payer = relationship("User", back_populates="payments_from", foreign_keys=[payer_id])
    payee = relationship("User", back_populates="payments_to", foreign_keys=[payee_id])

class Balance(Base):
    __tablename__ = "balances"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    balance = Column(Float, default=0.0)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    group = relationship("Group", back_populates="balances")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(Enum(ActionType), nullable=False)
    entity_type = Column(String, nullable=False)  # expense, member, balance
    entity_id = Column(Integer)
    details = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    group = relationship("Group", back_populates="audit_logs")
