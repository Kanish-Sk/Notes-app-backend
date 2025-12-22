"""
Fix user's MongoDB connection string encryption
This script will prompt for the connection string and re-encrypt it properly
"""
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
from bson import ObjectId

load_dotenv()

async def fix_connection_string():
    MONGODB_URL = os.getenv("MONGODB_URL")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "mindflow_ai")
    
    print("=" * 60)
    print("MongoDB Connection String Fix Tool")
    print("=" * 60)
    print()
    
    # Import encryption/decryption functions
    from user_database import encrypt_connection_string, decrypt_connection_string, verify_mongodb_connection
    
    print(f"📡 Connecting to main database...")
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client[DATABASE_NAME]
    
    try:
        await client.admin.command('ping')
        print("✅ Connected!\n")
        
        # Find the user
        email = input("Enter your email: ")
        user = await db.users.find_one({"email": email})
        
        if not user:
            print(f"❌ User {email} not found")
            return
        
        user_id = str(user['_id'])
        print(f"\n👤 Found user: {email}")
        print(f"   ID: {user_id}")
        print(f"   has_database: {user.get('has_database', False)}")
        
        if user.get('mongodb_connection_string'):
            print(f"   Encrypted connection string exists: ✅")
            
            # Try to decrypt
            try:
                decrypted = decrypt_connection_string(user.get('mongodb_connection_string'))
                print(f"   Decryption test: ✅ Success")
                print(f"   Connection string preview: {decrypted[:50]}...")
                
                # Try to connect with decrypted string
                print(f"\n🔍 Testing connection...")
                success, message = await verify_mongodb_connection(decrypted)
                if success:
                    print(f"   ✅ Connection works! {message}")
                    print(f"\n✅ Everything is working correctly!")
                    print(f"   Your data should be accessible.")
                    return
                else:
                    print(f"   ❌ Connection failed: {message}")
                    print(f"\n   The decrypted string doesn't connect.")
                    
            except Exception as e:
                print(f"   ❌ Decryption failed: {e}")
                print(f"\n   The connection string is corrupted or encryption key changed.")
        
        # Ask for new connection string
        print(f"\n📝 Let's fix this by entering a new connection string.")
        print(f"   Paste your MongoDB connection string:")
        new_conn_string = input("> ")
        
        if not new_conn_string.strip():
            print("❌ No connection string provided")
            return
        
        # Verify it works
        print(f"\n🔍 Testing new connection string...")
        success, message = await verify_mongodb_connection(new_conn_string)
        
        if not success:
            print(f"❌ Connection test failed: {message}")
            print(f"   Please check your connection string and try again.")
            return
        
        print(f"✅ Connection test passed!")
        
        # Encrypt and save
        print(f"\n💾 Encrypting and saving...")
        encrypted = encrypt_connection_string(new_conn_string)
        
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "mongodb_connection_string": encrypted,
                "has_database": True
            }}
        )
        
        print(f"✅ Connection string updated successfully!")
        print(f"\n🎉 All done! Try logging in again and your data should appear.")
        
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(fix_connection_string())
