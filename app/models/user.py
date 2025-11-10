from datetime import datetime, timedelta
import uuid
from typing import Optional, Dict, Any

from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import ValidationError

from app.schemas.base import UserCreate
from app.schemas.user import UserRead, Token

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<User(username={self.username}, email={self.email})>"

    def verify_password(self, password: str) -> bool:
        """Check password against hashed password."""
        return pwd_context.verify(password, self.password_hash)

    @staticmethod
    def hash_password(password: str) -> str:
        """has the password"""
        return pwd_context.hash(password)

    @staticmethod
    def generate_access_token(sub: str, expires_delta: Optional[timedelta] = None) -> str:
        """Generates JWT access token, used primarily for authentication and authorization"""
        payload = {"sub": sub}
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        payload["exp"] = expire
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def decode_access_token(token: str) -> Optional[uuid.UUID]:
        """Validates the JWT token and extracts the user ID"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub")
            return uuid.UUID(user_id) if user_id else None
        except (JWTError, ValueError):
            return None

    @classmethod
    def register_user(cls, db, user_data: Dict[str, Any]) -> "User":
        """Registers new user into DB"""
        password = user_data.get("password", "")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")

        if db.query(User).filter(
            (User.username == user_data.get("username")) |
            (User.email == user_data.get("email"))
        ).first():
            raise ValueError("Username or email already exists")

        try:
            user_create = UserCreate.model_validate(user_data)
        except ValidationError as e:
            raise ValueError(str(e))

        user = User(
            username=user_create.username,
            email=user_create.email,
            password_hash=cls.hash_password(user_create.password)
        )
        db.add(user)
        db.flush()
        return user

    @classmethod
    def authenticate_user(cls, db, username_or_email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticates user"""
        user = db.query(User).filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if not user or not user.verify_password(password):
            return None

        user_response = UserRead.model_validate(user)
        token = Token(
            access_token=cls.generate_access_token(str(user.id)),
            token_type="bearer",
            user=user_response
        )
        return token.model_dump()
    
    @classmethod
    def verify_token(cls, token: str) -> Optional[uuid.UUID]:
        """Verifies a JWT access token and return the corresponding user ID if valid"""
        try:
            return cls.decode_access_token(token)
        except Exception as e:
            return None

