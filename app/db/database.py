from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
import os

DB_PATH = os.getenv("DATABASE_URL", "sqlite:///./vulnerability_planner.db")

engine = create_engine(
    DB_PATH, 
    connect_args={"check_same_thread": False} if DB_PATH.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Auto-migration check: Ensure Sprint 4 threat intel columns exist in vulnerabilities table
    try:
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(vulnerabilities)")).fetchall()
            column_names = [row[1] for row in result]
            if column_names and "kev_known_exploited" not in column_names:
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN kev_known_exploited BOOLEAN DEFAULT 0"))
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN kev_date_added VARCHAR"))
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN kev_due_date VARCHAR"))
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN kev_required_action TEXT"))
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN epss_score FLOAT"))
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN epss_percentile FLOAT"))
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN threat_intel_multiplier FLOAT DEFAULT 1.0"))
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN threat_intel_last_updated VARCHAR"))
                conn.commit()
    except Exception:
        pass
