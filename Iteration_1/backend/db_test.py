"""
Simple DB connectivity test for RanScanAI
Reads DATABASE_URL from environment (or .env) and runs a simple query
"""
import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv(verbose=True)

# Require explicit env vars for security. Do not hard-code credentials.
DB_URL = os.getenv('DATABASE_URL')
if not DB_URL:
    user = os.getenv('POSTGRES_USER')
    pw = os.getenv('POSTGRES_PASSWORD')
    host = os.getenv('DB_HOST')
    port = os.getenv('DB_PORT', '5432')
    db = os.getenv('POSTGRES_DB')
    missing = [name for name, val in [('POSTGRES_USER', user), ('POSTGRES_PASSWORD', pw), ('DB_HOST', host), ('POSTGRES_DB', db)] if not val]
    if missing:
        raise SystemExit(f"Missing required environment variables: {', '.join(missing)}. Set DATABASE_URL or these vars and retry.")
    DB_URL = f'postgresql://{user}:{pw}@{host}:{port}/{db}'

print('Using DB URL from environment (hidden)')

engine = create_engine(DB_URL, future=True)

with engine.connect() as conn:
    res = conn.execute(text('SELECT 1'))
    print('Query result:', res.scalar())
    print('Connected OK')
