#!/usr/bin/env python3
"""
Check shared notes in database
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
from logger import setup_logging, get_logger

# Setup logging
setup_logging()
logger = get_logger(__name__)

load_dotenv()

async def check_shared_notes():
    # Connect to MongoDB
    mongo_uri = os.getenv("MONGODB_URL")
    client = AsyncIOMotorClient(mongo_uri)
    
    # Main database
    main_db = client[os.getenv("DATABASE_NAME", "notes_app")]
    
    logger.info("=" * 60)
    logger.info("CHECKING SHARED NOTES IN DATABASE")
    logger.info("=" * 60)
    
    # Check all notes in main DB
    logger.info("\n📊 MAIN DATABASE NOTES:")
    logger.info("-" * 60)
    notes = await main_db.notes.find({}).to_list(1000)
    logger.info(f"Total notes in main DB: {len(notes)}")
    
    for note in notes:
        shared_with = note.get("shared_with", [])
        if shared_with:
            logger.info(f"\n  ✉️  Note: {note.get('title', 'Untitled')}")
            logger.info(f"      ID: {note['_id']}")
            logger.info(f"      Owner: {note.get('user_id', 'Unknown')}")
            logger.info(f"      Shared with: {shared_with}")
    
    # Check if there are any shared notes
    shared_notes = await main_db.notes.find({
        "shared_with": {"$exists": True, "$ne": []}
    }).to_list(1000)
    logger.info(f"\nNotes with shared_with array: {len(shared_notes)}")
    
    # Check all folders in main DB
    logger.info("\n📊 MAIN DATABASE FOLDERS:")
    logger.info("-" * 60)
    folders = await main_db.folders.find({}).to_list(1000)
    logger.info(f"Total folders in main DB: {len(folders)}")
    
    for folder in folders:
        shared_with = folder.get("shared_with", [])
        if shared_with:
            logger.info(f"\n  📁 Folder: {folder.get('name', 'Untitled')}")
            logger.info(f"      ID: {folder['_id']}")
            logger.info(f"      Owner: {folder.get('user_id', 'Unknown')}")
            logger.info(f"      Shared with: {shared_with}")
    
    # Check user databases
    logger.info("\n📊 USER PERSONAL DATABASES:")
    logger.info("-" * 60)
    users = await main_db.users.find({}).to_list(1000)
    
    for user in users:
        user_db_name = user.get("personal_db_name")
        if user_db_name:
            logger.info(f"\n👤 User: {user.get('email')}")
            logger.info(f"   Personal DB: {user_db_name}")
            
            user_db = client[user_db_name]
            user_notes = await user_db.notes.find({}).to_list(1000)
            user_folders = await user_db.folders.find({}).to_list(1000)
            
            logger.info(f"   Notes: {len(user_notes)}")
            logger.info(f"   Folders: {len(user_folders)}")
            
            # Check for shared notes in user DB
            for note in user_notes:
                shared_with = note.get("shared_with", [])
                if shared_with:
                    logger.info(f"      ✉️  Shared note: {note.get('title')}")
                    logger.info(f"         Shared with: {shared_with}")
            
            # Check for shared folders in user DB
            for folder in user_folders:
                shared_with = folder.get("shared_with", [])
                if shared_with:
                    logger.info(f"      📁 Shared folder: {folder.get('name')}")
                    logger.info(f"         Shared with: {shared_with}")
    
    logger.info("\n" + "=" * 60)
    logger.info("DIAGNOSTIC COMPLETE")
    logger.info("=" * 60)
    
    client.close()

if __name__ == "__main__":
    asyncio.run(check_shared_notes())
