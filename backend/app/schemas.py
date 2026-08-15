from pydantic import BaseModel, HttpUrl
from typing import Optional, Any

class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = 'bearer'

class ScanCreate(BaseModel):
    url: HttpUrl

class ScanOut(BaseModel):
    id: int
    url: str
    result: Any
    created_at: str
