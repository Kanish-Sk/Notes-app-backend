#!/usr/bin/env python3
"""
Test script to verify MongoDB connection verification is working
"""
import asyncio
import sys
sys.path.append('/Users/kanish/Documents/MyProjects/AIProjects/notion-app/backend')

from user_database import verify_mongodb_connection

async def test_connection():
    # Test with a valid MongoDB connection string format (but likely invalid credentials)
    test_conn = "mongodb://localhost:27017"
    
    print("Testing MongoDB connection verification...")
    print(f"Connection string: {test_conn}")
    
    success, message = await verify_mongodb_connection(test_conn)
    
    print(f"Result: {'✅ Success' if success else '❌ Failed'}")
    print(f"Message: {message}")

if __name__ == "__main__":
    asyncio.run(test_connection())
