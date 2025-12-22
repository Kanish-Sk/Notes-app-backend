#!/usr/bin/env python3
"""
Check shared folders in the database
"""

import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

async def main():
    # Connect to main database
    mongodb_url = os.getenv("MONGODB_URL")
    client = AsyncIOMotorClient(mongodb_url)
    main_db = client.notes_app
    
    print("=" * 60)
    print("Checking shared_folders collection in main database")
    print("=" * 60)
    print()
    
    # Check if collection exists
    collections = await main_db.list_collection_names()
    print(f"Collections in main DB: {collections}")
    print()
    
    # Check shared_folders
    if "shared_folders" in collections:
        count = await main_db.shared_folders.count_documents({})
        print(f"Total shared folder references: {count}")
        print()
        
        if count > 0:
            print("Shared folder references:")
            async for ref in main_db.shared_folders.find():
                print(f"\n  Folder ID: {ref.get('folder_id')}")
                print(f"  Owner: {ref.get('owner_email')}")
                print(f"  Shared with: {ref.get('shared_with_email')}")
                print(f"  Folder name: {ref.get('folder_name')}")
                print(f"  Shared at: {ref.get('shared_at')}")
        else:
            print("❌ No shared folders found")
            print("\nTo share a folder:")
            print("1. Log in as owner")
            print("2. Right-click on a folder")
            print("3. Click 'Share'")
            print("4. Enter recipient email")
    else:
        print("❌ shared_folders collection does not exist yet")
        print("   It will be created when the first folder is shared")
    
    client.close()

if __name__ == '__main__':
    asyncio.run(main())
