import sqlite3
import json
import time

DB_PATH = "cache.db" # single file for sqlite3 database
TTL_SECONDS = 604800 # 7 days in seconds

def init_cache():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    # IF NOT EXISTS lets this run every startup without wiping existing data
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS lookups (
            ioc TEXT,
            source TEXT,
            result TEXT,
            fetched_at REAL
        )
    """)

    connection.commit()
    connection.close()


def write_cache(ioc, source, results):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()


    # ? placeholders to prevent SQL inject
    # json.dumps returns a dict, but SQLite stores text ... ex {"example": 1} -> '{"example": 1}' 
    # time.time() unix timestamp so TTL can later measure age via (now - fetched_at)
    cursor.execute("""
        INSERT INTO lookups (ioc, source, result, fetched_at)
        VALUES (?, ?, ?, ?) 
    """, (ioc, source, json.dumps(results), time.time()))

    connection.commit()
    connection.close()


def read_cache(ioc, source):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT result, fetched_at FROM lookups
        WHERE ioc = ? AND source = ?
    """, (ioc, source))

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    result, fetched_at = row
    # Check if the cached result is still valid based on TTL
    if time.time() - fetched_at > TTL_SECONDS:
        return None

    return json.loads(result)    