import pytest
import logging
from faker import Faker
from sqlalchemy.orm import Session
from app.models.user import User

fake = Faker()

@pytest.fixture
def registered_user(db_session):
    """Register a user and return the data and instance."""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "TestPass123"
    }
    user = User.register_user(db_session, user_data)
    db_session.commit()
    return db_session, user_data, user


def test_password_hashing_and_verification(db_session, fake_user_data):
    """
    Test that password hashing and verification work correctly.
    - The stored hash should not equal the original password.
    - verify_password should return True for correct password, False for wrong password.
    """
    password = "TestPass123"
    fake_user_data['password'] = password

    # Create and register user
    user = User.register_user(db_session, fake_user_data)
    db_session.commit()

    # Password hash should not match the plain password
    assert user.password_hash != password

    # verify_password should return True for correct password
    assert user.verify_password(password) is True

    # verify_password should return False for incorrect password
    assert user.verify_password("WrongPassword123") is False

def test_user_registration_process(db_session):
    """
    Test that a user can be successfully registered.
    - The user should be persisted in the database.
    - The password should be hashed.
    - Default flags like is_active and is_verified are correctly set.
    """
    # Prepare fake user data
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "TestPass123"
    }

    # Register user
    user = User.register_user(db_session, user_data)
    db_session.commit()

    # Assertions
    assert user.id is not None
    assert user.username == user_data["username"]
    assert user.email == user_data["email"]
    assert user.password_hash != user_data["password"]
    assert user.verify_password(user_data["password"]) is True

def test_user_registration_duplicate(db_session):
    """
    Test that registering a user with a duplicate username or email raises a ValueError.
    - First user is successfully registered.
    - Second user with same username OR email triggers a ValueError.
    """
    # Step 1: Register the first user
    user1_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "TestPass123"
    }
    user1 = User.register_user(db_session, user1_data)
    db_session.commit()

    # Step 2: Attempt duplicate username
    user2_data = {
        "username": user1_data["username"],   # duplicate username
        "email": fake.unique.email(),         # unique email
        "password": "TestPass123"
    }
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user2_data)

    # Step 3: Attempt duplicate email
    user3_data = {
        "username": fake.unique.user_name(), # unique username
        "email": user1_data["email"],        # duplicate email
        "password": "TestPass123"
    }
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user3_data)

def test_user_authentication_and_token(db_session):
    """
    Test that a registered user can authenticate successfully and receive a JWT token.
    - Registers a new user.
    - Authenticates with username and password.
    - Checks that the returned token and user details are correct.
    """
    # Step 1: Create and register a user
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "TestPass123"
    }
    user = User.register_user(db_session, user_data)
    db_session.commit()

    # Step 2: Authenticate the user
    auth_result = User.authenticate_user(
        db_session,
        user_data["username"],
        user_data["password"]
    )

    # Step 3: Assertions
    assert auth_result is not None
    assert "access_token" in auth_result
    assert auth_result["token_type"] == "bearer"
    assert "user" in auth_result
    assert auth_result["user"]["username"] == user_data["username"]
    assert auth_result["user"]["email"] == user_data["email"]

def test_user_authentication_failure(db_session):
    """
    Test authentication failure scenarios:
    - Wrong password
    - Nonexistent user
    """
    # Use a fake username/password that doesn't exist
    result_wrong_pass = User.authenticate_user(db_session, "nonexistent", "WrongPass123")
    assert result_wrong_pass is None

    # Register a valid user
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "TestPass123"
    }
    User.register_user(db_session, user_data)
    db_session.commit()

    # Wrong password attempt
    result_wrong_pass = User.authenticate_user(db_session, user_data["username"], "WrongPass123")
    assert result_wrong_pass is None

def test_unique_email_and_username_constraints(db_session):
    """
    Test that the database and model enforce uniqueness for email and username.
    - Register a user.
    - Attempt to register another user with the same email -> raises ValueError.
    - Attempt to register another user with the same username -> raises ValueError.
    """
    # Step 1: Register the first user
    user1_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "TestPass123"
    }
    user1 = User.register_user(db_session, user1_data)
    db_session.commit()

    # Step 2: Attempt to register a user with the same email
    user2_data = {
        "username": fake.unique.user_name(),  # different username
        "email": user1_data["email"],         # same email
        "password": "TestPass123"
    }
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user2_data)

    # Step 3: Attempt to register a user with the same username
    user3_data = {
        "username": user1_data["username"],   # same username
        "email": fake.unique.email(),         # different email
        "password": "TestPass123"
    }
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user3_data)

def test_token_creation_and_verification(db_session):
    """
    Test that a token can be created for a user and successfully verified.
    - Register a user.
    - Generate a token for that user.
    - Decode/verify the token.
    - Ensure the decoded ID matches the user ID.
    """
    # Step 1: Register a user
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "TestPass123"
    }
    user = User.register_user(db_session, user_data)
    db_session.commit()

    # Step 2: Generate a token
    token_str = User.generate_access_token(str(user.id))

    # Step 3: Verify the token
    decoded_user_id = User.decode_access_token(token_str)

    # Step 4: Assert the decoded ID matches the original user's ID
    assert decoded_user_id == user.id

def test_registration_fails_without_password(db_session):
    """
    Test that registering a user without a password raises a ValueError.
    - Prepare user data without the 'password' field.
    - Attempt to register the user.
    - Expect a ValueError indicating password requirements.
    """
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        # password is intentionally missing
    }

    with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
        User.register_user(db_session, user_data)