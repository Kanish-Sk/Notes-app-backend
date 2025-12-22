#!/usr/bin/env python3
"""
Migrate existing folder shares to the new shared_folders collection
"""

import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

async def main():
    mongodb_url = os.getenv("MONGODB_URL")
    client = AsyncIOMotorClient(mongodb_url)
    main_db = client.notes_app
    
    print("=" * 60)
    print("Migrating Folder Shares to New System")
    print("=" * 60)
    print()
    
    # Find the owner's user record
    owner = await main_db.users.find_one({"email": "kanishshivan@gmail.com"})
    if not owner:
        print("❌ Owner not found")
        return
    
    owner_id = str(owner["_id"])
    owner_email = owner["email"]
    owner_connection = owner.get("mongodb_connection_string")
    
    print(f"Owner: {owner_email}")
    print(f"Owner ID: {owner_id}")
    print(f"Connection string: {'✅ Set' if owner_connection else '❌ Not set'}")
    print()
    
    # Connect to owner's database
    if not owner_connection:
        print("❌ Owner has no connection string")
        return
    
    owner_client = AsyncIOMotorClient(owner_connection)
    owner_db = owner_client.user_data
    
    # Find folders with shared_with field
    folders_with_shares = await owner_db.folders.find({
        "user_id": owner_id,
        "shared_with": {"$exists": True, "$ne": []}
    }).to_list(100)
    
    print(f"Found {len(folders_with_shares)} folders with shares")
    print()
    
    migrated_count = 0
    for folder in folders_with_shares:
        folder_id = str(folder["_id"])
        folder_name = folder.get("name", "Untitled")
        shared_with = folder.get("shared_with", [])
        
        print(f"Folder: {folder_name} (ID: {folder_id})")
        print(f"  Shared with: {shared_with}")
        
        for recipient_email in shared_with:
            # Check if reference already exists
            existing = await main_db.shared_folders.find_one({
                "folder_id": folder_id,
                "owner_id": owner_id,
                "shared_with_email": recipient_email
            })
            
            if existing:
                print(f"  ✓ Reference already exists for {recipient_email}")
                continue
            
            # Create reference
            await main_db.shared_folders.insert_one({
                "folder_id": folder_id,
                "owner_id": owner_id,
                "owner_email": owner_email,
                "owner_connection_string": owner_connection,
                "shared_with_email": recipient_email,
                "folder_name": folder_name,
                "folder_parent_id": folder.get("parent_id"),
                "shared_at": datetime.utcnow(),
                "migrated": True  # Mark as migrated
            })
            
            print(f"  ✅ Created reference for {recipient_email}")
            migrated_count += 1
        
        print()
    
    print("=" * 60)
    print(f"✅ Migration complete!")
    print(f"   Created {migrated_count} new references")
    print("=" * 60)
    
    owner_client.close()
    client.close()

if __name__ == '__main__':
    asyncio.run(main())
