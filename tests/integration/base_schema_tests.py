import pytest
from uuid import uuid4
from datetime import datetime
from pydantic import ValidationError
from app.schemas.base import UserBase, PasswordMixin, UserCreate, UserLogin, UserRead

# =====================================
# UserBase Tests
# =====================================

def test_userbase_valid_data():
    """Validate that UserBase accepts correct email and username"""
    data = {"email": "test@example.com", "username": "testuser"}
    user = UserBase(**data)
    assert user.email == "test@example.com"
    assert user.username == "testuser"


def test_userbase_invalid_email():
    """Ensure UserBase raises ValidationError for invalid email format"""
    data = {"email": "invalid-email", "username": "testuser"}
    with pytest.raises(ValidationError) as exc_info:
        UserBase(**data)
    assert "value is not a valid email address" in str(exc_info.value)


def test_userbase_missing_fields():
    """Ensure UserBase raises ValidationError if required fields are missing"""
    data = {}
    with pytest.raises(ValidationError) as exc_info:
        UserBase(**data)

    assert "Field required" in str(exc_info.value)
    assert "email" in str(exc_info.value) or "username" in str(exc_info.value)


# =====================================
# PasswordMixin Tests
# =====================================

def test_password_mixin_valid_password():
    """Validate that PasswordMixin accepts a strong password."""
    data = {"password": "StrongPass1"}
    mixin = PasswordMixin(**data)
    assert mixin.password == "StrongPass1"


@pytest.mark.parametrize(
    "password,error_msg",
    [
        ("short", "Password must be at least 6 characters long"),
        ("alllowercase1", "Password must contain at least one uppercase letter"),
        ("ALLUPPERCASE1", "Password must contain at least one lowercase letter"),
        ("NoDigitsHere", "Password must contain at least one digit"),
        ("", "Password is required"),
    ]
)
def test_password_mixin_invalid_passwords(password, error_msg):
    """Check that PasswordMixin raises errors for invalid passwords"""
    data = {"password": password}
    with pytest.raises((ValueError, ValidationError)) as exc_info:
        PasswordMixin(**data)
    assert error_msg in str(exc_info.value)


# =====================================
# UserCreate Tests
# =====================================

def test_usercreate_valid():
    """Validate that UserCreate schema accepts valid user creation data"""
    data = {"email": "test@example.com", "username": "testuser", "password": "Password123"}
    user = UserCreate(**data)
    assert user.email == "test@example.com"
    assert user.username == "testuser"
    assert user.password == "Password123"


def test_usercreate_invalid_password():
    """Ensure UserCreate raises ValueError for invalid password"""
    data = {"email": "test@example.com", "username": "testuser", "password": "weak"}
    with pytest.raises(ValueError) as exc_info:
        UserCreate(**data)
    assert "Password must be at least 6 characters long" in str(exc_info.value)

@pytest.mark.parametrize(
    "username,error_msg",
    [
        ("ab", "ensure this value has at least 3 characters"),      # Too short
        ("a" * 51, "ensure this value has at most 50 characters"),   # Too long
    ]
)
def test_usercreate_username_length(username, error_msg):
    """Test that UserCreate rejects usernames that are too short or too long."""
    data = {
        "username": username,
        "email": "test@example.com",
        "password": "ValidPass123"
    }
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    assert error_msg in str(exc_info.value)
# =====================================
# UserLogin Tests
# =====================================

def test_userlogin_valid():
    """Validate that UserLogin schema accepts valid login credentials."""
    data = {"username": "testuser", "password": "Password123"}
    login = UserLogin(**data)
    assert login.username == "testuser"
    assert login.password == "Password123"


def test_userlogin_invalid_password():
    """Ensure UserLogin raises ValueError for invalid password."""
    data = {"username": "testuser", "password": "weak"}
    with pytest.raises(ValueError) as exc_info:
        UserLogin(**data)
    assert "Password must be at least 6 characters long" in str(exc_info.value)


# =====================================
# UserRead Tests
# =====================================

def test_userread_valid():
    """Validate that UserRead schema correctly stores and exposes user data."""
    data = {
        "id": uuid4(),
        "email": "test@example.com",
        "username": "testuser",
        "created_at": datetime.utcnow()
    }
    user = UserRead(**data)
    assert user.id == data["id"]
    assert user.email == "test@example.com"
    assert user.username == "testuser"
    assert isinstance(user.created_at, datetime)