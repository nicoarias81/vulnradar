"""
Modelos de datos y helpers de base de datos
"""
import sqlite3
from pathlib import Path

DB_PATH = Path("data/humo.db")

def get_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with open("schema.sql", "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print("Base de datos inicializada.")

if __name__ == "__main__":
    init_db()
