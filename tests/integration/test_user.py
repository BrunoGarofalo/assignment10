import pytest
import logging
from faker import Faker
from sqlalchemy.orm import Session
from app.models.user import User

# Initialize Faker
fake = Faker()

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)


# Helper to generate fake user data
def create_fake_user():
    return {
        "username": fake.user_name(),
        "email": fake.email(),
        "password": "Password123"  # valid password according to PasswordMixin
    }


# ======================================================================================
# User Registration Tests
# ======================================================================================

def test_register_user_success(db_session: Session):
    user_data = create_fake_user()
    logger.debug(f"Registering user: {user_data}")
    user = User.register_user(db_session, user_data)
    db_session.commit()
    logger.debug(f"User registered with ID: {user.id}")

    assert user.id is not None
    assert user.username == user_data["username"]
    assert user.email == user_data["email"]
    assert user.password_hash != user_data["password"]


def test_register_user_duplicate_username(db_session: Session):
    user_data1 = create_fake_user()
    user1 = User.register_user(db_session, user_data1)
    db_session.commit()

    # Duplicate username, different email
    user_data2 = create_fake_user()
    user_data2["username"] = user_data1["username"]
    user_data2["email"] = fake.email()

    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user_data2)


def test_register_user_duplicate_email(db_session: Session):
    user_data1 = create_fake_user()
    user1 = User.register_user(db_session, user_data1)
    db_session.commit()

    # Duplicate email, different username
    user_data2 = create_fake_user()
    user_data2["username"] = fake.user_name()
    user_data2["email"] = user_data1["email"]

    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user_data2)


def test_register_user_unique_username_and_email(db_session: Session):
    user_data1 = create_fake_user()
    user1 = User.register_user(db_session, user_data1)
    db_session.commit()

    user_data2 = create_fake_user()
    # Ensure both username and email are unique
    user_data2["username"] = fake.user_name()
    user_data2["email"] = fake.email()

    user2 = User.register_user(db_session, user_data2)
    db_session.commit()

    assert user2.username != user1.username
    assert user2.email != user1.email


def test_register_user_validation_error(db_session: Session):
    invalid_user_data = {"password": "ValidPassw1"}
    logger.debug(f"Testing validation error with data: {invalid_user_data}")

    with pytest.raises(ValueError) as exc_info:
        User.register_user(db_session, invalid_user_data)

    logger.debug(f"Caught ValueError: {exc_info.value}")
    assert "username" in str(exc_info.value) or "email" in str(exc_info.value)


# ======================================================================================
# User Authentication Tests
# ======================================================================================

def test_authenticate_user_success(db_session: Session):
    user_data = create_fake_user()
    user = User.register_user(db_session, user_data)
    db_session.commit()

    result = User.authenticate_user(db_session, user_data["username"], user_data["password"])

    assert result is not None
    assert "access_token" in result
    assert result["user"]["username"] == user_data["username"]
    assert result["user"]["email"] == user_data["email"]


def test_authenticate_user_failure_wrong_password(db_session: Session):
    user_data = create_fake_user()
    User.register_user(db_session, user_data)
    db_session.commit()

    result = User.authenticate_user(db_session, user_data["username"], "WrongPass123")
    assert result is None


def test_authenticate_user_failure_nonexistent_user(db_session: Session):
    result = User.authenticate_user(db_session, fake.user_name(), "AnyPassword1")
    assert result is None


# ======================================================================================
# Token Tests
# ======================================================================================

def test_access_token_generation(db_session: Session):
    user_data = create_fake_user()
    user = User.register_user(db_session, user_data)
    db_session.commit()

    token_str = User.generate_access_token(str(user.id))
    decoded_id = User.decode_access_token(token_str)

    assert decoded_id == user.id


def test_decode_access_token_invalid():
    invalid_token = "this.is.not.a.valid.token"
    result = User.decode_access_token(invalid_token)
    assert result is None


def test_decode_access_token_empty():
    result = User.decode_access_token("")
    assert result is None


def test_decode_access_token_random_string():
    token = "randomstring123"
    result = User.decode_access_token(token)
    assert result is None


# ======================================================================================
# User REPR test
# ======================================================================================

def test_user_repr():
    import uuid
    from datetime import datetime

    user = User(
        id=uuid.uuid4(),
        username=fake.user_name(),
        email=fake.email(),
        password_hash="fakehash",
        created_at=datetime.utcnow()
    )

    expected = f"<User(username={user.username}, email={user.email})>"
    assert repr(user) == expected
