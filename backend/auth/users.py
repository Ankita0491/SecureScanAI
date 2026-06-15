from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta

from database import SessionLocal
from models import User

SECRET_KEY = "change_this_secret_key_later"
ALGORITHM = "HS256"

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(
        plain_password,
        hashed_password
    )


def create_token(email: str):
    expire = datetime.utcnow() + timedelta(hours=24)

    payload = {
        "sub": email,
        "exp": expire
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def register_user(email: str, password: str):
    db = SessionLocal()

    try:
        existing_user = db.query(User).filter(
            User.email == email
        ).first()

        if existing_user:
            return None

        new_user = User(
            email=email,
            password=hash_password(password)
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return new_user

    finally:
        db.close()


def login_user(email: str, password: str):
    db = SessionLocal()

    try:
        user = db.query(User).filter(
            User.email == email
        ).first()

        if not user:
            return None

        if not verify_password(password, user.password):
            return None

        token = create_token(email)

        return {
            "access_token": token,
            "token_type": "bearer",
            "email": email
        }

    finally:
        db.close()