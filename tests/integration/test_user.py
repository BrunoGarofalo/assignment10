import pytest
import logging
from faker import Faker
from sqlalchemy.orm import Session
from app.models.user import User
from sqlalchemy.exc import IntegrityError

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


def test_partial_commit_rollback(db_session):
    """
    Demonstrate partial commits:
    - user1 is committed
    - user2 fails (duplicate email), triggers rollback, user1 remains
    - user3 is committed
    - final check ensures we only have user1 and user3
    """
    # User 1: valid
    user1_data = {
        "username": "user1",
        "email": "user1@example.com",
        "password": "Password123"
    }
    user1 = User.register_user(db_session, user1_data)
    db_session.commit()

    # User 2: duplicate email (will fail)
    user2_data = {
        "username": "user2",
        "email": "user1@example.com",  # duplicate email
        "password": "Password123"
    }

    # Attempt to commit user2 in a separate transaction block
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user2_data)
        db_session.commit()  # rollback should occur automatically in SQLAlchemy

    # User 3: valid
    user3_data = {
        "username": "user3",
        "email": "user3@example.com",
        "password": "Password123"
    }
    user3 = User.register_user(db_session, user3_data)
    db_session.commit()

    # Verify final state in database: only user1 and user3 exist
    users = db_session.query(User).all()
    usernames = [u.username for u in users]
    emails = [u.email for u in users]

    assert "user1" in usernames
    assert "user3" in usernames
    assert "user2" not in usernames
    assert "user1@example.com" in emails
    assert "user3@example.com" in emails
    assert "user2@example.com" not in emails

def test_create_single_user_with_faker(db_session):
    """Create a single user with Faker-generated data and verify it was saved."""
    # Generate fake user data
    user_data = {
        "username": fake.user_name(),
        "email": fake.unique.email(),
        "password": "Password123"  # Known password for testing
    }

    # Register user
    user = User.register_user(db_session, user_data)
    db_session.commit()

    # Fetch user from DB
    saved_user = db_session.query(User).filter_by(username=user.username).first()

    # Assertions
    assert saved_user is not None
    assert saved_user.username == user_data["username"]
    assert saved_user.email == user_data["email"]
    assert saved_user.password_hash != user_data["password"]  # Ensure password is hashed

def test_create_multiple_users_with_faker(db_session):
    """Create 4 users with Faker-generated data and verify they were all saved."""
    users_data = []
    saved_users = []

    # Create 4 users
    for _ in range(4):
        user_data = {
            "username": fake.unique.user_name(),
            "email": fake.unique.email(),
            "password": "Password123"  # Known password for testing
        }
        users_data.append(user_data)
        user = User.register_user(db_session, user_data)
        saved_users.append(user)

    # Commit all users
    db_session.commit()

    # Verify each user is saved in the DB
    for user_data in users_data:
        saved_user = db_session.query(User).filter_by(username=user_data["username"]).first()
        assert saved_user is not None
        assert saved_user.email == user_data["email"]
        assert saved_user.password_hash != user_data["password"]  # Ensure password is hashed

@pytest.fixture
def seed_users(db_session):
    """Create and commit 5 users for testing queries."""
    users = []
    for _ in range(5):
        user_data = {
            "username": fake.unique.user_name(),
            "email": fake.unique.email(),
            "password": "Password123"
        }
        user = User.register_user(db_session, user_data)
        users.append(user)
    db_session.commit()
    return users

def test_user_queries(db_session, seed_users):
    """Illustrate various query methods: count, filter, order."""
    
    # Count all users
    total_users = db_session.query(User).count()
    assert total_users >= 5  # At least the 5 seeded users
    
    # Filter by email (pick one from seeded users)
    target_email = seed_users[2].email
    filtered_user = db_session.query(User).filter_by(email=target_email).first()
    assert filtered_user is not None
    assert filtered_user.email == target_email
    
    # Order by id ascending
    users_ordered = db_session.query(User).order_by(User.id.asc()).all()
    assert len(users_ordered) >= 5
    ids = [u.id for u in users_ordered]
    assert ids == sorted(ids)  # Ensure ascending order

    # Order by id descending
    users_desc = db_session.query(User).order_by(User.id.desc()).all()
    ids_desc = [u.id for u in users_desc]
    assert ids_desc == sorted(ids_desc, reverse=True)  # Ensure descending order

def test_partial_transaction_rollback(db_session):
    """Demonstrate that a failed transaction triggers a rollback."""
    
    # Step 1: create a valid user
    user_data1 = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "Password123"
    }
    user1 = User.register_user(db_session, user_data1)
    db_session.commit()  # Commit user1
    assert db_session.query(User).filter_by(email=user_data1["email"]).first() is not None
    
    # Step 2: attempt to add a duplicate email to trigger IntegrityError
    user_data2 = {
        "username": fake.unique.user_name(),
        "email": user_data1["email"],  # duplicate email
        "password": "Password123"
    }
    
    with pytest.raises(ValueError):  # Our register_user raises ValueError for duplicates
        User.register_user(db_session, user_data2)
    
    db_session.rollback()  # Rollback the failed transaction
    
    # Step 3: ensure only user1 exists, user2 was not committed
    user_check = db_session.query(User).filter_by(email=user_data2["email"]).all()
    assert len(user_check) == 1  # Only original user1 remains
    
    # Step 4: add another valid user after rollback
    user_data3 = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "Password123"
    }
    user3 = User.register_user(db_session, user_data3)
    db_session.commit()
    
    # Verify both user1 and user3 exist
    all_users = db_session.query(User).filter(User.email.in_([user_data1["email"], user_data3["email"]])).all()
    assert len(all_users) == 2

def test_update_user_email(db_session):
    """Test updating a user's email and refreshing the session."""
    
    # Step 1: Create a user
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "Password123"
    }
    user = User.register_user(db_session, user_data)
    db_session.commit()
    
    original_email = user.email
    
    # Step 2: Update the email
    new_email = fake.unique.email()
    user.email = new_email
    db_session.commit()
    
    # Step 3: Refresh the session to get updated fields
    db_session.refresh(user)
    
    # Step 4: Assertions
    assert user.email == new_email
    assert user.email != original_email
    assert user.username == user_data["username"]  # unchanged

def test_duplicate_email_raises_value_error(db_session):
    """Test that creating two users with the same email raises ValueError."""

    email = fake.unique.email()
    user1_data = {
        "username": fake.unique.user_name(),
        "email": email,
        "password": "Password123"
    }
    User.register_user(db_session, user1_data)
    db_session.commit()

    # Second user with same email
    user2_data = {
        "username": fake.unique.user_name(),  # different username
        "email": email,                       # duplicate email
        "password": "Password123"
    }

    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user2_data)

def test_duplicate_username_raises_value_error(db_session):
    """Test that creating two users with the same username raises ValueError."""

    username = fake.unique.user_name()
    user1_data = {
        "username": username,
        "email": fake.unique.email(),
        "password": "Password123"
    }
    User.register_user(db_session, user1_data)
    db_session.commit()

    # Second user with same username
    user2_data = {
        "username": username,
        "email": fake.unique.email(),
        "password": "Password123"
    }

    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user2_data)

def test_partial_commit_user_remains(db_session):
    """
    - Create and commit a valid user
    - Attempt to create a duplicate user (same email) -> fails
    - Confirm the original user still exists
    """

    # Step 1: Create and commit the first valid user
    user1_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "password": "Password123"
    }
    user1 = User.register_user(db_session, user1_data)
    db_session.commit()

    # Step 2: Attempt to create a second user with the same email
    user2_data = {
        "username": fake.unique.user_name(),
        "email": user1_data["email"],  # duplicate email
        "password": "Password123"
    }

    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register_user(db_session, user2_data)

    # Step 3: Confirm the original user still exists in the database
    retrieved_user = db_session.query(User).filter_by(email=user1_data["email"]).first()
    assert retrieved_user is not None
    assert retrieved_user.username == user1_data["username"]
    assert retrieved_user.email == user1_data["email"]