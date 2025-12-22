"""
Quick script to check user data in MongoDB
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

async def check_user_data():
    MONGODB_URL = os.getenv("MONGODB_URL")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "mindflow_ai")
    
    print(f"📡 Connecting to MongoDB...")
    print(f"   Database: {DATABASE_NAME}")
    
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]
    
    try:
        # Ping to verify connection
        await client.admin.command('ping')
        print("✅ Connected to MongoDB!")
        
        # Find all users
        users = await db.users.find().to_list(100)
        print(f"\n📊 Found {len(users)} user(s):")
        
        for user in users:
            print(f"\n👤 User: {user.get('email')}")
            print(f"   ID: {user.get('_id')}")
            print(f"   has_database: {user.get('has_database', 'NOT SET')}")
            print(f"   mongodb_connection_string: {'SET' if user.get('mongodb_connection_string') else 'NOT SET'}")
            
            # Check if user has notes
            user_id = str(user.get('_id'))
            notes_count = await db.notes.count_documents({"user_id": user_id})
            print(f"   Notes in main DB: {notes_count}")
            
            # Check if user has LLM settings
            settings = await db.llmettings.find_one({"user_id": user_id})
            if settings:
                providers_count = len(settings.get('providers', []))
                print(f"   LLM Providers: {providers_count}")
                for i, provider in enumerate(settings.get('providers', [])):
                    print(f"      {i+1}. {provider.get('name')} ({provider.get('provider')}) - Active: {provider.get('is_active', False)}")
            else:
                print(f"   LLM Settings: NOT FOUND")
            
            # If user has custom database, check it
            if user.get('has_database') and user.get('mongodb_connection_string'):
                print(f"\n   🔍 Checking user's personal database...")
                try:
                    user_client = AsyncIOMotorClient(user.get('mongodb_connection_string'))
                    user_db = user_client['user_data']
                    
                    notes_count = await user_db.notes.count_documents({"user_id": user_id})
                    print(f"      Notes in user DB: {notes_count}")
                    
                    settings = await user_db.llm_settings.find_one({"user_id": user_id})
                    if settings:
                        providers_count = len(settings.get('providers', []))
                        print(f"      LLM Providers in user DB: {providers_count}")
                    
                    user_client.close()
                except Exception as e:
                    print(f"      ❌ Error accessing user DB: {e}")
        
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(check_user_data())
