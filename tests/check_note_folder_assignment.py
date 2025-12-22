"""
Check notes and their folder assignments for a specific user
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

async def check_notes_folders():
    # Connect to main database
    mongo_uri = os.getenv("MONGODB_URI")
    client = AsyncIOMotorClient(mongo_uri)
    main_db = client.notes_app
    
    # Get user
    user_email = "kanishshivan@gmail.com"
    user = await main_db.users.find_one({"email": user_email})
    
    if not user:
        print(f"User {user_email} not found!")
        return
    
    print(f"\n👤 User: {user.get('full_name')} ({user.get('email')})")
    print(f"📊 User ID: {user['_id']}")
    
    # Connect to user's database
    user_conn_string = user.get("personal_connection_string") or user.get("owner_connection_string")
    if not user_conn_string:
        print("❌ No connection string found!")
        return
    
    user_client = AsyncIOMotorClient(user_conn_string)
    user_db = user_client.user_data
    
    # Get all folders
    folders = await user_db.folders.find({}).to_list(1000)
    print(f"\n📁 Found {len(folders)} folders:")
    for folder in folders:
        print(f"   - {folder.get('name')} (ID: {folder['_id']})")
        if folder.get('parent_id'):
            print(f"     Parent ID: {folder.get('parent_id')}")
    
    # Get all notes
    notes = await user_db.notes.find({}).to_list(1000)
    print(f"\n📝 Found {len(notes)} notes:")
    for note in notes:
        folder_id = note.get('folder_id')
        folder_name = "Root (No folder)"
        if folder_id:
            folder = await user_db.folders.find_one({"_id": folder_id}) or await user_db.folders.find_one({"_id": str(folder_id)})
            if folder:
                folder_name = folder.get('name', 'Unknown')
            else:
                folder_name = f"Unknown folder (ID: {folder_id})"
        
        print(f"   - '{note.get('title')}' ")
        print(f"     Folder: {folder_name}")
        print(f"     folder_id: {folder_id} (type: {type(folder_id)})")
    
    await client.close()
    await user_client.close()

if __name__ == "__main__":
    asyncio.run(check_notes_folders())
