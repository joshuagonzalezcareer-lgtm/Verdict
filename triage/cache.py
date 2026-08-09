import sqlite3
import json
import time

DB_PATH = "cache.db" # single file for sqlite3 database

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