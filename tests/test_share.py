#!/usr/bin/env python3
"""Test script to manually create a share between two users"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
import sys

# Load .env from the backend directory
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Add backend to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from user_database import get_user_database
from bson import ObjectId
from datetime import datetime

async def test_share():
    mongo_uri = os.getenv('MONGODB_URL')
    client = AsyncIOMotorClient(mongo_uri)
    main_db = client[os.getenv('DATABASE_NAME', 'notes_app')]
    
    # Get two users with databases
    users = await main_db.users.find({"has_database": True}).to_list(10)
    if len(users) < 2:
        print("Need at least 2 users with databases to test sharing")
        return
    
    owner = users[0]
    recipient = users[1]
    
    print(f"Owner: {owner.get('email')}")
    print(f"Recipient: {recipient.get('email')}")
    
    # Connect to owner's database
    owner_db = await get_user_database(
        str(owner['_id']),
        owner.get('mongodb_connection_string'),
        database_name="user_data"
    )
    
    # Get a note from owner
    note = await owner_db.notes.find_one({"user_id": str(owner['_id'])})
    if not note:
        print("Owner has no notes to share")
        return
    
    note_id = str(note['_id'])
    print(f"Note to share: {note.get('title')} (ID: {note_id})")
    
    # Simulate sharing - update owner's DB
    recipient_email = recipient.get('email').lower()
    share_record = {
        "email": recipient_email,
        "shared_at": datetime.utcnow(),
        "recipient_user_id": str(recipient['_id'])
    }
    
    await owner_db.notes.update_one(
        {"_id": ObjectId(note_id)},
        {
            "$addToSet": {"shared_with": recipient_email},
            "$push": {"share_history": share_record}
        }
    )
    print(f"Updated owner's note with shared_with: {recipient_email}")
    
    # Create shared_notes reference in main DB
    await main_db.shared_notes.update_one(
        {
            "note_id": note_id,
            "owner_id": str(owner['_id']),
            "shared_with_email": recipient_email
        },
        {
            "$set": {
                "note_id": note_id,
                "owner_id": str(owner['_id']),
                "owner_email": owner.get('email').lower(),
                "owner_connection_string": owner.get('mongodb_connection_string'),
                "shared_with_email": recipient_email,
                "note_title": note.get("title", "Untitled"),
                "note_folder_id": note.get("folder_id"),
                "shared_at": datetime.utcnow()
            }
        },
        upsert=True
    )
    print(f"Created shared_notes reference in main DB")
    
    # Verify
    shared_ref = await main_db.shared_notes.find_one({"shared_with_email": recipient_email})
    print(f"\nVerification - shared_notes record: {shared_ref is not None}")
    if shared_ref:
        print(f"  Note: {shared_ref.get('note_title')}")
        print(f"  Owner: {shared_ref.get('owner_email')}")
        print(f"  Recipient: {shared_ref.get('shared_with_email')}")
    
    client.close()
    print("\n✅ Test share created successfully!")

if __name__ == "__main__":
    asyncio.run(test_share())
