#!/usr/bin/env python3
"""
Gmail API Token Generator

This script generates token.json for Gmail API authentication.
Run this once to authenticate and save credentials.
"""

import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def generate_token():
    """Generate token.json for Gmail API"""
    creds = None
    token_file = 'token.json'
    credentials_file = 'credentials.json'
    
    # Check if credentials.json exists
    if not os.path.exists(credentials_file):
        print(f"❌ Error: {credentials_file} not found!")
        print(f"Please create {credentials_file} with your OAuth credentials.")
        return False
    
    # The file token.json stores the user's access and refresh tokens
    if os.path.exists(token_file):
        print(f"⚠️  {token_file} already exists!")
        response = input("Do you want to regenerate it? (y/n): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return False
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("🔄 Refreshing expired credentials...")
            creds.refresh(Request())
        else:
            print("🌐 Opening browser for authentication...")
            print("📧 Please sign in with your Gmail account")
            print("✅ Grant permission to send emails")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            # Desktop Client IDs allow dynamic ports (port=0)
            creds = flow.run_local_server(port=0)
        
        # Save the credentials for the next run
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
        
        print(f"\n✅ Success! {token_file} has been created!")
        print(f"📁 Location: {os.path.abspath(token_file)}")
        print("\n🔒 Important:")
        print(f"   - Keep {token_file} secure")
        print(f"   - Don't commit it to Git (already in .gitignore)")
        print(f"   - This token allows sending emails from your account")
        return True
    else:
        print(f"✅ {token_file} is already valid!")
        return True

if __name__ == '__main__':
    print("=" * 60)
    print("Gmail API Token Generator")
    print("=" * 60)
    print()
    
    success = generate_token()
    
    if success:
        print("\n🎉 You're all set!")
        print("   Your backend can now send emails via Gmail API")
    else:
        print("\n❌ Token generation failed")
        print("   Please check the errors above and try again")
