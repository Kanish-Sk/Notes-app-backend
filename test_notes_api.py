#!/usr/bin/env python3
"""
Test what the notes API returns for the recipient
"""

import requests
import json

BACKEND_URL = "http://127.0.0.1:8000"

# Login as recipient
print("Logging in as recipient (kanish.s@onebillsoftware.com)...")
login_resp = requests.post(f"{BACKEND_URL}/api/auth/login", json={
    "email": "kanish.s@onebillsoftware.com",
    "password": "Test@123"
})


if login_resp.status_code != 200:
    print(f"❌ Login failed: {login_resp.text}")
    exit(1)

token = login_resp.json()["access_token"]
print("✅ Login successful\n")

# Get notes
print("Fetching notes...")
notes_resp = requests.get(f"{BACKEND_URL}/api/notes", headers={
    "Authorization": f"Bearer {token}"
})

if notes_resp.status_code != 200:
    print(f"❌ Failed to fetch notes: {notes_resp.text}")
    exit(1)

notes = notes_resp.json()
print(f"✅ Received {len(notes)} notes\n")

print("=" * 60)
print("Note Details:")
print("=" * 60)

for i, note in enumerate(notes, 1):
    print(f"\nNote {i}:")
    print(f"  Title: {note.get('title', 'Untitled')}")
    print(f"  ID: {note.get('id') or note.get('_id')}")
    print(f"  User ID: {note.get('user_id')}")
    print(f"  is_shared: {note.get('is_shared')}")
    print(f"  shared_by: {note.get('shared_by')}")
    print(f"  folder_id: {note.get('folder_id')}")
