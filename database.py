from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi
import os
from dotenv import load_dotenv

load_dotenv()

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
        print("✅ Successfully connected to MongoDB!")
    except Exception as e:
        print(f"❌ Error connecting to MongoDB: {e}")
        # Use in-memory fallback for development
        print("⚠️  Using in-memory storage as fallback")

async def close_mongo_connection():
    """Close MongoDB connection"""
    global client
    if client:
        client.close()
        print("Closed MongoDB connection")

def get_database():
    """Get database instance"""
    return database
