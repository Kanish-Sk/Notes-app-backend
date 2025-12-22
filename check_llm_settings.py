"""
Check LLM settings in user's personal database
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
from bson import ObjectId

load_dotenv()

async def check_llm_settings():
    MONGODB_URL = os.getenv("MONGODB_URL")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "mindflow_ai")
    
    print("🔍 Checking LLM Settings...")
    
    # Import decryption
    from user_database import decrypt_connection_string
    
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]
    
    try:
        # Get user
        user = await db.users.find_one({"email": "kanishshivan@gmail.com"})
        user_id = str(user['_id'])
        
        print(f"👤 User ID: {user_id}")
        
        # Check main database
        print(f"\n📦 Main Database ({DATABASE_NAME}):")
        settings_main = await db.llm_settings.find_one({"user_id": user_id})
        if settings_main:
            print(f"   ✅ LLM Settings found!")
            print(f"   Providers: {len(settings_main.get('providers', []))}")
            for p in settings_main.get('providers', []):
                print(f"      - {p.get('name')} ({p.get('provider')})")
        else:
            print(f"   ❌ No LLM settings found")
        
        # Check user's personal database
        if user.get('has_database') and user.get('mongodb_connection_string'):
            print(f"\n📦 User's Personal Database:")
            decrypted = decrypt_connection_string(user.get('mongodb_connection_string'))
            user_client = AsyncIOMotorClient(decrypted)
            user_db = user_client['user_data']
            
            settings_user = await user_db.llm_settings.find_one({"user_id": user_id})
            if settings_user:
                print(f"   ✅ LLM Settings found!")
                print(f"   Providers: {len(settings_user.get('providers', []))}")
                for p in settings_user.get('providers', []):
                    print(f"      - {p.get('name')} ({p.get('provider')}) - Active: {p.get('is_active')}")
            else:
                print(f"   ❌ No LLM settings found")
            
            user_client.close()
        
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(check_llm_settings())
