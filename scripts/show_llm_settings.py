"""
Show full LLM settings document
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
import json

load_dotenv()

async def show_llm_settings():
    MONGODB_URL = os.getenv("MONGODB_URL")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "mindflow_ai")
    
    from user_database import decrypt_connection_string
    
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]
    
    try:
        user = await db.users.find_one({"email": "kanishshivan@gmail.com"})
        user_id = str(user['_id'])
        
        # Check user's personal database
        decrypted = decrypt_connection_string(user.get('mongodb_connection_string'))
        user_client = AsyncIOMotorClient(decrypted)
        user_db = user_client['user_data']
        
        settings = await user_db.llm_settings.find_one({"user_id": user_id})
        
        if settings:
            print("📄 LLM Settings Document:")
            print("="* 60)
            # Convert ObjectId to string for JSON serialization
            settings['_id'] = str(settings['_id'])
            print(json.dumps(settings, indent=2, default=str))
        else:
            print("❌ No LLM settings found")
        
        user_client.close()
        
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(show_llm_settings())
