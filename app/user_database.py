"""
User-specific database connection management for multi-tenant architecture.
Each user can have their own MongoDB cluster for storing their data.
"""
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Optional, Dict
import asyncio
from cryptography.fernet import Fernet
import os
from .logger import get_logger

# Setup logger
logger = get_logger(__name__)

# Connection pool for user databases
user_db_connections: Dict[str, AsyncIOMotorClient] = {}
connection_locks: Dict[str, asyncio.Lock] = {}

# Encryption for connection strings
ENCRYPTION_KEY = os.getenv("DB_ENCRYPTION_KEY", Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY if isinstance(ENCRYPTION_KEY, bytes) else ENCRYPTION_KEY.encode())


def encrypt_connection_string(connection_string: str) -> str:
    """Encrypt MongoDB connection string for secure storage"""
    return cipher_suite.encrypt(connection_string.encode()).decode()


def decrypt_connection_string(encrypted_string: str) -> str:
    """Decrypt MongoDB connection string"""
    return cipher_suite.decrypt(encrypted_string.encode()).decode()


async def verify_mongodb_connection(connection_string: str) -> tuple[bool, str]:
    """
    Verify that a MongoDB connection string is valid and connectable.
    Returns: (success: bool, message: str)
    """
    try:
        # Try to connect
        client = AsyncIOMotorClient(
            connection_string,
            serverSelectionTimeoutMS=5000  # 5 second timeout
        )
        
        # Try to ping the database
        await client.admin.command('ping')
        
        # Try to list databases (to ensure we have proper permissions)
        await client.list_database_names()
        
        # Close the test connection
        client.close()
        
        return True, "Connection successful"
    
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ MongoDB Connection Error: {error_msg}")  # Debug logging
        logger.info(f"   Connection string starts with: {connection_string[:20]}...")  # Show beginning of connection string
        
        if "authentication" in error_msg.lower():
            return False, "Authentication failed. Please check your credentials."
        elif "timeout" in error_msg.lower():
            return False, "Connection timeout. Please check your connection string and network."
        elif "dns" in error_msg.lower():
            return False, "DNS resolution failed. Please check your connection string."
        else:
            return False, f"Connection failed: {error_msg}"


async def get_user_database(user_id: str, connection_string: str, database_name: str = "user_data"):
    """
    Get or create a database connection for a specific user.
    Uses connection pooling to reuse connections.
    """
    # Create a unique key for this user's connection
    conn_key = f"{user_id}_{database_name}"
    
    # Get or create a lock for this connection
    if conn_key not in connection_locks:
        connection_locks[conn_key] = asyncio.Lock()
    
    async with connection_locks[conn_key]:
        # Return existing connection if available
        if conn_key in user_db_connections:
            return user_db_connections[conn_key][database_name]
        
        # Create new connection
        try:
            # Decrypt the connection string
            decrypted_conn_string = decrypt_connection_string(connection_string)
            
            # Create client
            client = AsyncIOMotorClient(
                decrypted_conn_string,
                maxPoolSize=10,
                minPoolSize=2,
                serverSelectionTimeoutMS=5000
            )
            
            # Store the client
            user_db_connections[conn_key] = client
            
            # Return the specific database
            return client[database_name]
        
        except Exception as e:
            logger.error(f"Error creating user database connection: {e}")
            raise


async def close_user_database(user_id: str, database_name: str = "user_data"):
    """Close a user's database connection"""
    conn_key = f"{user_id}_{database_name}"
    
    if conn_key in user_db_connections:
        user_db_connections[conn_key].close()
        del user_db_connections[conn_key]
    
    if conn_key in connection_locks:
        del connection_locks[conn_key]


async def close_all_user_databases():
    """Close all user database connections (for shutdown)"""
    for client in user_db_connections.values():
        client.close()
    
    user_db_connections.clear()
    connection_locks.clear()
