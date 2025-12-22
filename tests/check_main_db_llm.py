"""
Check if LLM settings are in main database instead
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
import json

load_dotenv()

async def check_main_db_settings():
    MONGODB_URL = os.getenv("MONGODB_URL")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "mindflow_ai")
    
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]
    
    try:
        # Get all llm_settings documents
        all_settings = await db.llm_settings.find().to_list(100)
        
        print(f"📦 All LLM Settings in Main Database ({DATABASE_NAME}):")
        print("=" * 60)
        
        if not all_settings:
            print("❌ No LLM settings found in main database")
        else:
            for settings in all_settings:
                settings['_id'] = str(settings['_id'])
                print(f"\n📄 Document for user_id: {settings.get('user_id')}")
                print(json.dumps(settings, indent=2, default=str))
                print("-" * 60)
        
    finally:
        client.close()

if __name == "__main__":
    asyncio.run(check_main_db_settings())
