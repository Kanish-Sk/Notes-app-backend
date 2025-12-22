#!/usr/bin/env python3
"""
Test folder sharing by directly calling the share endpoint
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

# Configuration
BACKEND_URL = "http://127.0.0.1:8000/api"

# You need to provide these
OWNER_EMAIL = "kanishshivan@gmail.com"  # Owner who will share the folder
OWNER_PASSWORD = "your_password_here"  # Replace with actual password
RECIPIENT_EMAIL = "kanish.s@onebillsoftware.com"  # Who will receive the share

def login(email, password):
    """Login and get access token"""
    response = requests.post(f"{BACKEND_URL}/../auth/login", json={
        "email": email,
        "password": password
    })
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        print(f"❌ Login failed: {response.text}")
        return None

def get_folders(token):
    """Get all folders for the user"""
    response = requests.get(f"{BACKEND_URL}/folders", headers={
        "Authorization": f"Bearer {token}"
    })
    if response.status_code == 200:
        return response.json()
    return []

def share_folder(token, folder_id, recipient_email):
    """Share a folder with a recipient"""
    response = requests.post(
        f"{BACKEND_URL}/folders/{folder_id}/share",
        json={"email": recipient_email},
        headers={"Authorization": f"Bearer {token}"}
    )
    return response

def main():
    print("=" * 60)
    print("Testing Folder Sharing")
    print("=" * 60)
    print()
    
    # Login as owner
    print(f"1. Logging in as owner ({OWNER_EMAIL})...")
    if OWNER_PASSWORD == "your_password_here":
        print()
        print("❌ ERROR: Please edit this script and set OWNER_PASSWORD")
        print("   Or use the UI to share a folder instead")
        return
    
    token = login(OWNER_EMAIL, OWNER_PASSWORD)
    if not token:
        return
    print("   ✅ Login successful")
    print()
    
    # Get folders
    print("2. Getting folders...")
    folders = get_folders(token)
    print(f"   Found {len(folders)} folders")
    print()
    
    if not folders:
        print("   ❌ No folders found. Please create a folder first.")
        return
    
    # Show folders
    print("   Available folders:")
    for i, folder in enumerate(folders):
        print(f"   [{i}] {folder.get('name', 'Untitled')} (ID: {folder['id']})")
    print()
    
    # Share first folder
    folder_to_share = folders[0]
    print(f"3. Sharing folder '{folder_to_share.get('name')}' with {RECIPIENT_EMAIL}...")
    response = share_folder(token, folder_to_share['id'], RECIPIENT_EMAIL)
    
    if response.status_code == 200:
        print("   ✅ Folder shared successfully!")
        print(f"   Response: {response.json()}")
    else:
        print(f"   ❌ Failed to share: {response.text}")

if __name__ == '__main__':
    main()
