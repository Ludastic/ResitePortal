# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from passlib.context import CryptContext
from jose import JWTError, jwt
import os
from sqlalchemy import create_engine, Column, String, Integer, Enum, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://student:QAZxsw123@91.184.232.244:5432/students")
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    name = Column(String)
    password_hash = Column(String)
    role = Column(String)  # student, teacher, admin


class Resit(Base):
    __tablename__ = "resits"
    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"))
    subject = Column(String)
    date = Column(String)  # ISO format
    status = Column(String)
    #pending / approved / rejected
    teacher_note = Column(String, nullable=True)


Base.metadata.create_all(bind=engine)


# Pydantic models
class UserBase(BaseModel):
    email: str
    name: str
    role: str


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int


class ResitBase(BaseModel):
    student_id: int
    subject: str
    date: datetime


class ResitCreate(ResitBase):
    pass


class ResitResponse(ResitBase):
    id: int
    status: str
    teacher_note: Optional[str]


class Token(BaseModel):
    access_token: str
    token_type: str


# Auth setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Auth utils
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


# Routes
@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        email=user_data.email,
        name=user_data.name,
        password_hash=hashed_password,
        role=user_data.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/users", response_model=List[UserResponse])
async def get_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return db.query(User).all()


@app.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
        user_id: int,
        user_data: UserBase,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    for key, value in user_data.dict().items():
        setattr(db_user, key, value)

    db.commit()
    db.refresh(db_user)
    return db_user


@app.delete("/users/{user_id}")
async def delete_user(
        user_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")

    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()
    return {"message": "User deleted"}


@app.get("/resits", response_model=List[ResitResponse])
async def get_resits(db: Session = Depends(get_db)):
    return db.query(Resit).all()


@app.post("/resits", response_model=ResitResponse)
async def create_resit(
        resit_data: ResitCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can create resits")

    db_resit = Resit(
        **resit_data.dict(),
        status="pending"
    )
    db.add(db_resit)
    db.commit()
    db.refresh(db_resit)
    return db_resit


@app.put("/resits/{resit_id}", response_model=ResitResponse)
async def update_resit_status(
        resit_id: int,
        status: str,
        teacher_note: Optional[str] = None,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    if current_user.role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can update resits")

    db_resit = db.query(Resit).filter(Resit.id == resit_id).first()
    if not db_resit:
        raise HTTPException(status_code=404, detail="Resit not found")

    db_resit.status = status
    db_resit.teacher_note = teacher_note
    db.commit()
    db.refresh(db_resit)
    return db_resit


# class UserService:
#     @staticmethod
#     def get_user_by_email(db: Session, email: str):
#         return db.query(User).filter(User.email == email).first()
#
#     @staticmethod
#     def create_user(db: Session, user_data: UserCreate):
#         hashed_password = get_password_hash(user_data.password)
#         db_user = User(
#             email=user_data.email,
#             name=user_data.name,
#             password_hash=hashed_password,
#             role=user_data.role
#         )
#         db.add(db_user)
#         db.commit()
#         db.refresh(db_user)
#         return db_user
#
#     @staticmethod
#     def get_all_users(db: Session):
#         return db.query(User).all()
#
#     @staticmethod
#     def update_user(db: Session, user_id: int, user_data: UserBase):
#         db_user = db.query(User).filter(User.id == user_id).first()
#         if not db_user:
#             return None
#
#         for key, value in user_data.dict().items():
#             setattr(db_user, key, value)
#
#         db.commit()
#         db.refresh(db_user)
#         return db_user
#
#     @staticmethod
#     def delete_user(db: Session, user_id: int):
#         db_user = db.query(User).filter(User.id == user_id).first()
#         if not db_user:
#             return False
#
#         db.delete(db_user)
#         db.commit()
#         return True
#
# class ResitService:
#     @staticmethod
#     def get_all_resits(db: Session):
#         return db.query(Resit).all()
#
#     @staticmethod
#     def create_resit(db: Session, resit_data: ResitCreate):
#         db_resit = Resit(**resit_data.dict(), status="pending")
#         db.add(db_resit)
#         db.commit()
#         db.refresh(db_resit)
#         return db_resit
#
#     @staticmethod
#     def update_resit_status(db: Session, resit_id: int, status: str, teacher_note: str = None):
#         db_resit = db.query(Resit).filter(Resit.id == resit_id).first()
#         if not db_resit:
#             return None
#
#         db_resit.status = status
#         db_resit.teacher_note = teacher_note
#         db.commit()
#         db.refresh(db_resit)
#        return db_resit