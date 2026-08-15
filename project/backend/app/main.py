from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base
from .routes import auth as auth_router
from .routes import scan as scan_router
import os

Base.metadata.create_all(bind=engine)

app = FastAPI(title='Web App Attack Surface Analyzer')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(scan_router.router)

@app.get('/')
def root():
    return {'status': 'ok'}
