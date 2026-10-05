import os
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# ==========================================================
# CONFIGURAÇÃO DE CONEXÃO COM O BANCO DE DADOS (MYSQL / CLOUD)
# ==========================================================
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "1234")
    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT = os.getenv("MYSQL_PORT", "3306")
    MYSQL_DB = os.getenv("MYSQL_DB", "usuario")
    
    senha_codificada = quote_plus(MYSQL_PASSWORD)
    DATABASE_URL = f"mysql+pymysql://{MYSQL_USER}:{senha_codificada}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"

# Ajuste caso o provider envie "mysql://" ao invés de "mysql+pymysql://"
if DATABASE_URL.startswith("mysql://"):
    DATABASE_URL = DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)

engine = create_engine(
    DATABASE_URL,
    pool_recycle=3600
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()