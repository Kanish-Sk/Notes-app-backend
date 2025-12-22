#!/usr/bin/env python3
"""
Check if folder "TEst" was shared with the new mechanism
"""

import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

async def main():
    mongodb_url = os.getenv("MONGODB_URL")
    client = AsyncIOMotorClient(mongodb_url)
    main_db = client.notes_app
    
    print("=" * 60)
    print("Checking all databases and collections")
    print("=" * 60)
    print()
    
    # List all collections
    collections = await main_db.list_collection_names()
    print(f"Collections in main DB: {collections}")
    print()
    
    # Check shared_folders
    if "shared_folders" in collections:
        count = await main_db.shared_folders.count_documents({})
        print(f"✅ shared_folders collection exists with {count} documents")
        
        if count > 0:
            async for doc in main_db.shared_folders.find():
                print(f"\n  Folder: {doc.get('folder_name')}")
                print(f"  Owner: {doc.get('owner_email')}")
                print(f"  Shared with: {doc.get('shared_with_email')}")
    else:
        print("❌ shared_folders collection does not exist")
    
    print()
    print("Checking folders collection for 'TEst' folder:")
    folder = await main_db.folders.find_one({"name": "TEst"})
    if folder:
        print(f"  Found in main DB (shouldn't be here)")
        print(f"  shared_with: {folder.get('shared_with', [])}")
    else:
        print("  Not in main DB (correct)")
    
    client.close()

if __name__ == '__main__':
    asyncio.run(main())
