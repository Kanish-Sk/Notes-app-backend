#!/usr/bin/env python3
"""Test script to verify shared notes are returned for recipient"""
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

async def verify_share():
    mongo_uri = os.getenv('MONGODB_URL')
    client = AsyncIOMotorClient(mongo_uri)
    main_db = client[os.getenv('DATABASE_NAME', 'notes_app')]
    
    # Get the recipient user
    recipient_email = "raja.jaisankar@onebillsoftware.com"
    recipient = await main_db.users.find_one({"email": recipient_email})
    
    if not recipient:
        print(f"Recipient {recipient_email} not found")
        return
    
    print(f"== Checking notes for recipient: {recipient_email} ==\n")
    
    # Connect to recipient's database
    recipient_db = await get_user_database(
        str(recipient['_id']),
        recipient.get('mongodb_connection_string'),
        database_name="user_data"
    )
    
    # Get recipient's owned notes
    owned_notes = await recipient_db.notes.find({
        "user_id": str(recipient['_id'])
    }).to_list(100)
    
    print(f"Owned notes: {len(owned_notes)}")
    for n in owned_notes:
        print(f"  - {n.get('title')} (ID: {n.get('_id')})")
    
    # Get shared notes from main DB
    shared_refs = await main_db.shared_notes.find({
        "shared_with_email": recipient_email.lower()
    }).to_list(100)
    
    print(f"\nShared notes references: {len(shared_refs)}")
    
    all_notes = list(owned_notes)
    
    # Group by owner
    owners_notes = {}
    for ref in shared_refs:
        owner_id = ref.get("owner_id")
        if owner_id not in owners_notes:
            owners_notes[owner_id] = {
                "connection_string": ref.get("owner_connection_string"),
                "owner_email": ref.get("owner_email"),
                "note_ids": []
            }
        owners_notes[owner_id]["note_ids"].append(ref.get("note_id"))
    
    # Fetch notes from each owner's database
    for owner_id, owner_data in owners_notes.items():
        if not owner_data["connection_string"]:
            print(f"⚠️ Owner {owner_id} has no connection string")
            continue
        
        try:
            print(f"\nFetching from owner: {owner_data['owner_email']}")
            owner_db = await get_user_database(
                owner_id,
                owner_data["connection_string"],
                database_name="user_data"
            )
            
            # Fetch the actual notes from owner's DB
            note_object_ids = [ObjectId(nid) for nid in owner_data["note_ids"] if ObjectId.is_valid(nid)]
            print(f"  Looking for notes: {[str(nid) for nid in note_object_ids]}")
            
            if note_object_ids:
                shared_notes = await owner_db.notes.find({
                    "_id": {"$in": note_object_ids}
                }).to_list(100)
                
                print(f"  Found {len(shared_notes)} shared notes")
                
                # Mark these as shared and add owner info
                for note in shared_notes:
                    note["is_shared"] = True
                    note["shared_by"] = owner_data["owner_email"]
                    note["original_owner_id"] = owner_id
                    print(f"    - {note.get('title')} (ID: {note.get('_id')})")
                
                all_notes.extend(shared_notes)
                
        except Exception as e:
            print(f"❌ Failed to fetch shared notes from owner {owner_id}: {e}")
    
    print(f"\n== TOTAL NOTES FOR RECIPIENT: {len(all_notes)} ==")
    print(f"  Owned: {len(owned_notes)}")
    print(f"  Shared: {len(all_notes) - len(owned_notes)}")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(verify_share())
