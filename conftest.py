import pytest
from app.db.database import init_db

@pytest.fixture(autouse=True)
def ensure_db_tables_exist():
    """
    Autouse fixture ensuring SQLite database tables exist for all test runs.
    """
    init_db()
