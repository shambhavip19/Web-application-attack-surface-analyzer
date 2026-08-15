from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db
from ..auth import hash_password, verify_password, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post('/register')
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail='Username already exists')
    u = models.User(username=user.username, password_hash=hash_password(user.password))
    db.add(u)
    db.commit()
    db.refresh(u)
    return {"id": u.id, "username": u.username}

@router.post('/login', response_model=schemas.Token)
def login(user: schemas.UserCreate, db: Session = Depends(get_db)):
    u = db.query(models.User).filter(models.User.username == user.username).first()
    if not u or not verify_password(user.password, u.password_hash):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token = create_access_token(str(u.id))
    return {"access_token": token}
