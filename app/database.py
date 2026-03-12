import asyncpg
import os
from dotenv import load_dotenv
from .logger import get_logger

load_dotenv()

logger = get_logger(__name__)

NEON_DATABASE_URL = os.getenv("NEON_DATABASE_URL")

pool: asyncpg.Pool | None = None


async def connect_to_db():
    global pool
    try:
        pool = await asyncpg.create_pool(
            NEON_DATABASE_URL,
            min_size=2,
            max_size=10,
            command_timeout=60,
            statement_cache_size=0,
        )
        logger.info("✅ Connected to Neon (PostgreSQL)")
    except Exception as e:
        logger.error(f"❌ Failed to connect to Neon: {e}")
        raise


async def close_db():
    global pool
    if pool:
        await pool.close()
        logger.info("Closed Neon connection pool")


def get_pool() -> asyncpg.Pool:
    return pool
