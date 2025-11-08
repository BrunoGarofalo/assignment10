# ======================================================================================
# tests/integration/test_user.py
# ======================================================================================
# Purpose: Test the simplified User model interactions with the database using pytest.
#          Assumes 'conftest.py' provides db_session fixture and managed_db_session.
# ======================================================================================

import pytest
import logging
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models.user import User
from tests.conftest import create_fake_user, managed_db_session

logger = logging.getLogger(__name__)

# ======================================================================================
# Basic Database Tests
# ======================================================================================

def test_database_connection(db_session):
    """Verify database connection works."""
    result = db_session.execute(text("SELECT 1"))
    assert result.scalar() == 1
    logger.info("Database connection verified.")


def test_managed_session_context():
    """Test the managed_db_session context manager and rollback behavior."""
    with managed_db_session() as session:
        session.execute(text("SELECT 1"))
        try:
            session.execute(text("SELECT * FROM nonexistent_table"))
        except Exception as e:
            assert "nonexistent_table" in str(e)


# ======================================================================================
# User Creation & Session Handling
# ======================================================================================

def test_create_single_user(db_session):
    """Create a user and verify persistence."""
    user_data = create_fake_user()
    user = User(
        username=user_data["username"],
        email=user_data["email"],
        password_hash=User.hash_password(user_data["password"])
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.id is not None
    assert user.email == user_data["email"]
    assert user.username == user_data["username"]
    logger.info(f"Created user: {user.username}")


def test_unique_constraints(db_session):
    """Verify unique constraints for username and email."""
    data1 = create_fake_user()
    user1 = User(
        username=data1["username"],
        email=data1["email"],
        password_hash=User.hash_password(data1["password"])
    )
    db_session.add(user1)
    db_session.commit()

    # Duplicate email
    data2 = create_fake_user()
    data2["email"] = data1["email"]
    user2 = User(
        username=data2["username"],
        email=data2["email"],
        password_hash=User.hash_password(data2["password"])
    )
    db_session.add(user2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Duplicate username
    data3 = create_fake_user()
    data3["username"] = data1["username"]
    user3 = User(
        username=data3["username"],
        email=data3["email"],
        password_hash=User.hash_password(data3["password"])
    )
    db_session.add(user3)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_bulk_insert_users(db_session):
    """Test bulk insertion of multiple users."""
    users_data = [create_fake_user() for _ in range(5)]
    users = [
        User(
            username=data["username"],
            email=data["email"],
            password_hash=User.hash_password(data["password"])
        )
        for data in users_data
    ]
    db_session.bulk_save_objects(users)
    db_session.commit()

    count = db_session.query(User).count()
    assert count >= 5
    logger.info(f"Bulk inserted {len(users)} users.")


def test_transaction_rollback(db_session):
    """Ensure rollback occurs on failed transaction."""
    initial_count = db_session.query(User).count()
    user_data = create_fake_user()
    user = User(
        username=user_data["username"],
        email=user_data["email"],
        password_hash=User.hash_password(user_data["password"])
    )
    db_session.add(user)

    try:
        db_session.execute(text("SELECT * FROM nonexistent_table"))
        db_session.commit()
    except Exception:
        db_session.rollback()

    final_count = db_session.query(User).count()
    assert final_count == initial_count


# ======================================================================================
# Query & Update Tests
# ======================================================================================

def test_query_users(db_session, seed_users):
    """Test querying by email and ordering."""
    first_seed = seed_users[0]
    found = db_session.query(User).filter_by(email=first_seed.email).first()
    assert found is not None

    all_users = db_session.query(User).order_by(User.email).all()
    assert len(all_users) >= len(seed_users)


def test_update_user_email(db_session, seed_users):
    """Update a user's email and verify."""
    user = seed_users[0]
    new_email = f"updated_{user.email}"
    user.email = new_email
    db_session.commit()
    db_session.refresh(user)
    assert user.email == new_email
