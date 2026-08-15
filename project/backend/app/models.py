from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from sqlalchemy.dialects.mysql import JSON
from .database import Base

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, server_default=func.now())

class Scan(Base):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    url = Column(String(2048), nullable=False)
    result = Column(Text)  # JSON string
    created_at = Column(DateTime, server_default=func.now())
