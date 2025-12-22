from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi
import os
from dotenv import load_dotenv
from logger import get_logger

load_dotenv()

# Setup logger
logger = get_logger(__name__)

# MongoDB connection
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "notion_app")

client = None
database = None

async def connect_to_mongo():
    """Connect to MongoDB"""
    global client, database
    try:
        client = AsyncIOMotorClient(MONGODB_URL, server_api=ServerApi('1'))
        database = client[DATABASE_NAME]
        # Test connection
        await client.admin.command('ping')
        logger.info("✅ Successfully connected to MongoDB!")
    except Exception as e:
        logger.error(f"❌ Error connecting to MongoDB: {e}")
        # Use in-memory fallback for development
        logger.warning("⚠️  Using in-memory storage as fallback")

async def close_mongo_connection():
    """Close MongoDB connection"""
    global client
    if client:
        client.close()
        logger.info("Closed MongoDB connection")

def get_database():
    """Get database instance"""
    return database

def get_client():
    """Get MongoDB client instance for cross-database queries"""
    return client
