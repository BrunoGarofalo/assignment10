import pytest
import logging
from app.models.user import User
from app.schemas.user import UserResponse, Token
from tests.conftest import create_fake_user
from sqlalchemy.orm import Session

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# ======================================================================================
# User Registration Tests
# ======================================================================================

def test_register_user_success(db_session):
    """Test creating a new user successfully."""
    user_data = create_fake_user()
    logger.debug(f"Registering user: {user_data}")
    user = User.register_user(db_session, user_data)
    db_session.commit()
    logger.debug(f"User registered with ID: {user.id}")

    assert user.id is not None
    assert user.username == user_data["username"]
    assert user.email == user_data["email"]
    assert user.password_hash != user_data["password"]


def test_register_user_duplicate(db_session):
    """Test that registering a user with duplicate username/email fails."""
    user_data = create_fake_user()
    logger.debug("Registering first user for duplicate test")
    user1 = User.register_user(db_session, user_data)
    db_session.commit()

    logger.debug("Attempting duplicate registration")
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user_data)


def test_register_user_validation_error(db_session: Session):
    """Test that register_user raises a ValueError when Pydantic validation fails."""
    invalid_user_data = {
        "password": "ValidPassw1"
    }
    logger.debug(f"Testing validation error with data: {invalid_user_data}")

    with pytest.raises(ValueError) as exc_info:
        User.register_user(db_session, invalid_user_data)

    logger.debug(f"Caught ValueError: {exc_info.value}")
    assert "username" in str(exc_info.value) or "email" in str(exc_info.value)


# ======================================================================================
# User Authentication Tests
# ======================================================================================

def test_authenticate_user_success(db_session):
    """Test authenticating a registered user."""
    user_data = create_fake_user()
    logger.debug(f"Registering user for auth test: {user_data}")
    user = User.register_user(db_session, user_data)
    db_session.commit()

    logger.debug(f"Authenticating user: {user_data['username']}")
    result = User.authenticate_user(db_session, user_data["username"], user_data["password"])
    logger.debug(f"Authentication result: {result}")

    assert result is not None
    assert "access_token" in result
    assert result["user"]["username"] == user_data["username"]
    assert result["user"]["email"] == user_data["email"]


def test_authenticate_user_failure(db_session):
    """Test authentication failure for non-registered or wrong password."""
    user_data = create_fake_user()
    
    logger.debug(f"Authenticating non-registered user: {user_data['username']}")
    result = User.authenticate_user(db_session, user_data["username"], user_data["password"])
    assert result is None

    logger.debug("Registering user for wrong password test")
    user = User.register_user(db_session, user_data)
    db_session.commit()

    logger.debug("Authenticating with wrong password")
    result_wrong_password = User.authenticate_user(db_session, user_data["username"], "WrongPass123")
    assert result_wrong_password is None


# ======================================================================================
# Token Tests
# ======================================================================================

def test_access_token_generation(db_session):
    """Test JWT token creation and decoding."""
    user_data = create_fake_user()
    logger.debug(f"Registering user for token test: {user_data}")
    user = User.register_user(db_session, user_data)
    db_session.commit()

    token_str = User.generate_access_token(str(user.id))
    decoded_id = User.decode_access_token(token_str)
    logger.debug(f"Token: {token_str}, Decoded ID: {decoded_id}")

    assert decoded_id == user.id


def test_decode_access_token_invalid():
    """Test that decode_access_token returns None for invalid JWT tokens."""
    invalid_token = "this.is.not.a.valid.token"
    logger.debug(f"Decoding invalid token: {invalid_token}")
    result = User.decode_access_token(invalid_token)
    assert result is None


def test_decode_access_token_empty():
    """Test that decode_access_token returns None for empty token."""
    result = User.decode_access_token("")
    logger.debug("Decoding empty token")
    assert result is None


def test_decode_access_token_random_string():
    """Test that decode_access_token returns None for random string."""
    token = "randomstring123"
    logger.debug(f"Decoding random string token: {token}")
    result = User.decode_access_token(token)
    assert result is None


# ======================================================================================
# User REPR test
# ======================================================================================

def test_user_repr():
    """Test the __repr__ method of the User model."""
    import uuid
    from datetime import datetime

    user = User(
        id=uuid.uuid4(),
        username="testuser",
        email="test@example.com",
        password_hash="fakehash",
        created_at=datetime.utcnow()
    )

    expected = f"<User(username={user.username}, email={user.email})>"
    logger.debug(f"Testing __repr__: {repr(user)}")
    assert repr(user) == expected
