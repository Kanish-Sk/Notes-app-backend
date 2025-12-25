from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from bson import ObjectId
from typing import Optional, List, Dict
import os
import json
import traceback
from dotenv import load_dotenv
import httpx


from app.models import (
    NoteCreate, NoteUpdate, NoteInDB, 
    UserCreate, UserInDB, UserLogin, 
    FolderCreate, FolderUpdate, FolderInDB, 
    ShareNoteRequest, LLMSettings, ChatMessage, 
    Token, RefreshTokenData, GoogleAuthRequest, 
    ForgotPasswordRequest, VerifyResetCodeRequest, ResetPasswordRequest, 
    MongoDBConnectionRequest, MongoDBConnectionResponse, 
    TestLLMConnectionRequest, TestLLMConnectionResponse, 
    CloudinaryTestRequest, CloudinaryTestResponse, CloudinaryUpdateRequest,
    AIRequest, AIResponse, ChatCreate, ChatUpdate, ChatInDB, 
    LLMProvider, LLMSettingsInDB, User
)
from app.auth import (
    get_password_hash, verify_password, 
    authenticate_user, create_access_token, create_refresh_token,
    verify_refresh_token, get_current_user, get_current_active_user,
    get_user_by_email, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
)
from app.database import connect_to_mongo, close_mongo_connection, get_database, get_client
from app.user_database import get_user_database
from app.email_utils import send_password_reset_email, send_share_notification_email
from app.logger import setup_logging, get_logger
from pymongo import ReturnDocument

load_dotenv()

# Setup logging
setup_logging()
logger = get_logger(__name__)

# In-memory storage fallback
notes_storage = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await connect_to_mongo()
    yield
    # Shutdown
    await close_mongo_connection()

app = FastAPI(title="Notion-like Notes API", version="1.0.0", lifespan=lifespan)

# CORS middleware - Allow localhost for development and frontend URL from env for production
frontend_url = os.getenv("FRONTEND_URL", "")
allowed_origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:3000",
]

# Add production frontend URL if provided
if frontend_url:
    allowed_origins.append(frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== Notes Routes ====================

@app.get("/")
async def root():
    return {"message": "Notion-like Notes API", "version": "1.0.0"}

# ==================== Database Helper ====================

async def get_user_data_db(current_user: UserInDB):
    """
    Get the appropriate database for storing user data (notes, folders, chats).
    Returns user's personal database if configured, otherwise returns main database.
    """
    # If user has configured their own database, use it
    if current_user.has_database and current_user.mongodb_connection_string:
        from app.user_database import get_user_database
        try:
            user_db = await get_user_database(
                current_user.id,
                current_user.mongodb_connection_string,
                database_name="user_data"
            )
            return user_db
        except Exception as e:
            logger.warning(f"⚠️  Failed to connect to user's database: {e}")
            logger.info(f"   Falling back to main database")
            # Fallback to main database if user's DB fails
            return get_database()
    else:
        # Use main database
        return get_database()

def get_decrypted_cloudinary_credentials(user_dict: dict) -> dict:
    """
    Helper to decrypt Cloudinary credentials from user document.
    Returns dict with decrypted credentials or None values.
    """
    from app.user_database import decrypt_connection_string
    
    result = {
        "cloudinary_cloud_name": user_dict.get("cloudinary_cloud_name"),  # Plain text
        "cloudinary_api_key": None,
        "cloudinary_api_secret": None
    }
    
    # Decrypt API key if exists
    if user_dict.get("cloudinary_api_key"):
        try:
            result["cloudinary_api_key"] = decrypt_connection_string(user_dict["cloudinary_api_key"])
        except Exception as e:
            logger.warning(f"Failed to decrypt cloudinary_api_key: {e}")
    
    # Decrypt API secret if exists
    if user_dict.get("cloudinary_api_secret"):
        try:
            result["cloudinary_api_secret"] = decrypt_connection_string(user_dict["cloudinary_api_secret"])
        except Exception as e:
            logger.warning(f"Failed to decrypt cloudinary_api_secret: {e}")
    
    return result


async def cleanup_note_images(note_content: str, user_dict: dict):
    """
    Find and delete all Cloudinary images in note content.
    Used as a background task.
    """
    if not note_content or not user_dict:
        return
        
    creds = get_decrypted_cloudinary_credentials(user_dict)
    if not creds.get('cloudinary_cloud_name') or not creds.get('cloudinary_api_key') or not creds.get('cloudinary_api_secret'):
        return
        
    import re
    import base64
    
    # Find all Cloudinary URLs
    cloudinary_pattern = r'https://res\.cloudinary\.com/[^\"\'\)\s]+'
    urls = re.findall(cloudinary_pattern, note_content)
    
    if not urls:
        return
        
    public_ids = []
    for url in urls:
        # Extract public_id from URL
        # Handle versions v12345/ and also nested folders
        match = re.search(r'/upload/(?:v\d+/)?(.+?)(?:\.[^.]+)?$', url)
        if match:
            public_ids.append(match.group(1))
            
    if not public_ids:
        return
        
    # Remove duplicates
    public_ids = list(set(public_ids))
        
    try:
        auth_string = f"{creds['cloudinary_api_key']}:{creds['cloudinary_api_secret']}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                "DELETE",
                f"https://api.cloudinary.com/v1_1/{creds['cloudinary_cloud_name']}/resources/image/upload",
                headers={"Authorization": f"Basic {encoded_auth}"},
                json={"public_ids": public_ids}
            )
            if response.status_code == 200:
                logger.info(f"🗑️ Successfully cleaned up {len(public_ids)} images from Cloudinary")
            else:
                logger.warning(f"⚠️ Cloudinary cleanup returned status {response.status_code}: {response.text}")
    except Exception as e:
        logger.error(f"Error cleaning up Cloudinary images: {e}")

@app.get("/api/stats")
async def get_statistics():
    """Get app statistics - no auth required"""
    db = get_database()
    if db is None:
        return {"users": 0, "notes": 0}
    
    try:
        # Count total users
        users_count = await db.users.count_documents({})
        
        # Sum notes_count from all users
        pipeline = [
            {"$group": {"_id": None, "total_notes": {"$sum": "$notes_count"}}}
        ]
        result = await db.users.aggregate(pipeline).to_list(length=1)
        notes_count = result[0]["total_notes"] if result else 0
        
        return {
            "users": users_count,
            "notes": notes_count
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return {"users": 0, "notes": 0}

# ==================== Authentication Routes ====================

@app.post("/api/auth/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """Register a new user with email and password"""
    from app.user_database import verify_mongodb_connection, encrypt_connection_string
    
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Check if user already exists
    existing_user = await get_user_by_email(user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Verify MongoDB connection string if provided
    encrypted_connection_string = None
    has_database = False
    
    if user_data.mongodb_connection_string:
        success, message = await verify_mongodb_connection(user_data.mongodb_connection_string)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"MongoDB connection failed: {message}"
            )
        # Encrypt the connection string
        encrypted_connection_string = encrypt_connection_string(user_data.mongodb_connection_string)
        has_database = True
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    user_dict = {
        "email": user_data.email,
        "full_name": user_data.full_name,
        "hashed_password": hashed_password,
        "provider": "email",
        "refresh_tokens": [],
        "is_active": True,
        "mongodb_connection_string": encrypted_connection_string,
        "has_database": has_database,
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_dict)
    created_user = await db.users.find_one({"_id": result.inserted_id})
    user_in_db = UserInDB(**{**created_user, "_id": str(created_user["_id"])})
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_in_db.email}, 
        expires_delta=access_token_expires
    )
    
    # Create refresh token
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        data={"sub": user_in_db.email},
        expires_delta=refresh_token_expires
    )
    
    # Store refresh token in database
    await db.users.update_one(
        {"_id": ObjectId(user_in_db.id)},
        {"$push": {"refresh_tokens": refresh_token}}
    )
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        user={
            "id": user_in_db.id,
            "email": user_in_db.email,
            "full_name": user_in_db.full_name,
            "picture": user_in_db.picture,
            "has_database": user_in_db.has_database
        }
    )

@app.post("/api/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    """Login with email and password"""
    user = await authenticate_user(user_data.email, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, 
        expires_delta=access_token_expires
    )
    
    # Create refresh token
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        data={"sub": user.email},
        expires_delta=refresh_token_expires
    )
    
    # Store refresh token in database
    db = get_database()
    user_dict = None
    if db is not None:
        await db.users.update_one(
            {"_id": ObjectId(user.id)},
            {"$push": {"refresh_tokens": refresh_token}}
        )
        # Fetch full user document for Cloudinary credentials
        user_dict = await db.users.find_one({"_id": ObjectId(user.id)})
    
    # Prepare user response with decrypted Cloudinary credentials
    user_response = {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "picture": user.picture,
        "has_database": user.has_database,
        "mongodb_connection_string": user.mongodb_connection_string
    }
    
    # Add decrypted Cloudinary credentials if available
    if user_dict:
        cloudinary_creds = get_decrypted_cloudinary_credentials(user_dict)
        user_response.update(cloudinary_creds)
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        user=user_response
    )

@app.post("/api/auth/google", response_model=Token)
async def google_auth(auth_data: GoogleAuthRequest):
    """Authenticate with Google OAuth using JWT credential from One Tap"""
    credential = auth_data.credential
    google_client_id = os.getenv("GOOGLE_CLIENT_ID")
    
    try:
        # Verify the Google JWT credential
        async with httpx.AsyncClient() as client:
            # Get Google's public keys for verification
            response = await client.get("https://www.googleapis.com/oauth2/v3/certs")
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to fetch Google certificates"
                )
            
            # For simplicity, we'll verify by getting user info directly
            user_info_response = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={credential}"
            )
            
            if user_info_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid Google credential"
                )
            
            google_user = user_info_response.json()
            
            # Verify the token is for our app
            if google_user.get("aud") != google_client_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid token audience"
                )
        
        # Check if user exists
        db = get_database()
        if db is None:
            raise HTTPException(status_code=500, detail="Database not available")
        
        user = await get_user_by_email(google_user["email"])
        
        if not user:
            # Create new user from Google data
            user_dict = {
                "email": google_user["email"],
                "full_name": google_user.get("name"),
                "picture": google_user.get("picture"),
                "provider": "google",
                "refresh_tokens": [],
                "is_active": True,
                "has_database": False,
                "mongodb_connection_string": None,
                "created_at": datetime.utcnow()
            }
            
            result = await db.users.insert_one(user_dict)
            created_user = await db.users.find_one({"_id": result.inserted_id})
            user = UserInDB(**{**created_user, "_id": str(created_user["_id"])})
        
        # Create tokens
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.email},
            expires_delta=access_token_expires
        )
        
        refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = create_refresh_token(
            data={"sub": user.email},
            expires_delta=refresh_token_expires
        )
        
        # Store refresh token
        await db.users.update_one(
            {"_id": ObjectId(user.id)},
            {"$push": {"refresh_tokens": refresh_token}}
        )
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            user={
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "picture": user.picture,
                "has_database": user.has_database,
                "mongodb_connection_string": user.mongodb_connection_string
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google auth error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google authentication failed: {str(e)}"
        )

@app.post("/api/auth/refresh", response_model=Token)
async def refresh_access_token(token_data: RefreshTokenData):
    """Refresh access token using refresh token"""
    email = await verify_refresh_token(token_data.refresh_token)
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = await get_user_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    # Create new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    
    # Return same refresh token (rotation can be added later)
    return Token(
        access_token=access_token,
        refresh_token=token_data.refresh_token,
        user={
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "picture": user.picture
        }
    )

@app.post("/api/auth/logout")
async def logout(token_data: RefreshTokenData, current_user: UserInDB = Depends(get_current_user)):
    """Logout user by invalidating refresh token"""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    db = get_database()
    if db is not None:
        # Remove the refresh token from user's list
        await db.users.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$pull": {"refresh_tokens": token_data.refresh_token}}
        )
    
    return {"message": "Successfully logged out"}

@app.get("/api/auth/me", response_model=dict)
async def get_current_user_info(current_user: UserInDB = Depends(get_current_active_user)):
    """Get current user information"""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "picture": current_user.picture,
        "provider": current_user.provider
    }

@app.post("/api/auth/forgot-password")
async def forgot_password(request_data: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    """Send password reset code via email"""
    import random
    from email_utils import send_password_reset_email
    
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    user = await get_user_by_email(request_data.email)
    
    # For security, always return success even if user doesn't exist
    # This prevents email enumeration attacks
    if not user:
        return {"message": "If the email exists, a password reset code has been sent"}
    
    # Generate a 6-digit reset code
    reset_code = str(random.randint(100000, 999999))
    
    # Set expiry to 15 minutes from now
    reset_code_expires = datetime.utcnow() + timedelta(minutes=15)
    
    # Store the reset code and expiry in the database
    await db.users.update_one(
        {"_id": ObjectId(user.id)},
        {"$set": {
            "reset_code": reset_code,
            "reset_code_expires": reset_code_expires
        }}
    )
    
    # Send email in background (non-blocking) - API responds immediately
    background_tasks.add_task(
        send_password_reset_email,
        to_email=user.email,
        reset_code=reset_code,
        user_name=user.full_name
    )
    
    return {
        "message": "If the email exists, a password reset code has been sent",
        "expires_in_minutes": 15
    }

@app.post("/api/auth/verify-reset-code")
async def verify_reset_code(request_data: VerifyResetCodeRequest):
    """Verify a password reset code"""
    
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    user = await get_user_by_email(request_data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or reset code"
        )
    
    # Check if reset code exists
    if not user.reset_code or not user.reset_code_expires:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No reset code requested for this email"
        )
    
    # Check if code matches
    if user.reset_code != request_data.code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset code"
        )
    
    # Check if code has expired
    if datetime.utcnow() > user.reset_code_expires:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset code has expired. Please request a new one."
        )
    
    return {"message": "Reset code is valid", "valid": True}

@app.post("/api/auth/reset-password")
async def reset_password(request_data: ResetPasswordRequest):
    """Reset password using reset code"""
    
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Get user
    user = await get_user_by_email(request_data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or reset code"
        )
    
    # Check if reset code exists
    if not user.reset_code or not user.reset_code_expires:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No reset code requested for this email"
        )
    
    # Verify the reset code
    if user.reset_code != request_data.code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset code"
        )
    
    # Check if code has expired
    if datetime.utcnow() > user.reset_code_expires:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset code has expired. Please request a new one."
        )
    
    # Hash the new password
    hashed_password = get_password_hash(request_data.new_password)
    
    # Update password and clear reset code
    await db.users.update_one(
        {"_id": ObjectId(user.id)},
        {"$set": {
            "hashed_password": hashed_password,
            "reset_code": None,
            "reset_code_expires": None
        }}
    )
    
    return {"message": "Password successfully reset"}

# ==================== User Search Routes ====================

@app.get("/api/users/search")
async def search_users(query: str, current_user: UserInDB = Depends(get_current_active_user)):
    """Search for users by email or name (for sharing notes/folders)"""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    if not query or len(query) < 2:
        return []
    
    # Search by email or full_name (case-insensitive), exclude current user
    search_regex = {"$regex": query, "$options": "i"}
    users = await db.users.find({
        "$or": [
            {"email": search_regex},
            {"full_name": search_regex}
        ],
        "is_active": True,
        "email": {"$ne": current_user.email}  # Exclude current user
    }).limit(10).to_list(10)
    
    # Return user info (excluding sensitive data)
    return [
        {
            "id": str(user["_id"]),
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "picture": user.get("picture")
        }
        for user in users
    ]

# ==================== MongoDB Connection Routes ====================

@app.post("/api/verify-mongodb", response_model=MongoDBConnectionResponse)
async def verify_mongodb_connection_endpoint(request: MongoDBConnectionRequest):
    """Verify MongoDB connection string (no auth required for testing during registration)"""
    from app.user_database import verify_mongodb_connection
    
    success, message = await verify_mongodb_connection(request.connection_string)
    return MongoDBConnectionResponse(success=success, message=message)

@app.post("/api/user/update-database")
async def update_user_database(
    request: MongoDBConnectionRequest,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Update user's MongoDB connection string (for Google login users)"""
    from app.user_database import verify_mongodb_connection, encrypt_connection_string
    
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Verify the connection
    success, message = await verify_mongodb_connection(request.connection_string)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"MongoDB connection failed: {message}"
        )
    
    # Encrypt and save
    encrypted_connection_string = encrypt_connection_string(request.connection_string)
    
    await db.users.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$set": {
            "mongodb_connection_string": encrypted_connection_string,
            "has_database": True
        }}
    )
    
    # Fetch and return updated user
    updated_user = await db.users.find_one({"_id": ObjectId(current_user.id)})
    if updated_user:
        # Don't send encrypted connection string to frontend
        user_response = {
            "id": str(updated_user["_id"]),
            "email": updated_user.get("email"),
            "full_name": updated_user.get("full_name"),
            "picture": updated_user.get("picture"),
            "has_database": updated_user.get("has_database", False),
            "provider": updated_user.get("provider", "email")
        }
        return {
            "message": "Database connection updated successfully",
            "user": user_response
        }
    
    return {"message": "Database connection updated successfully", "has_database": True}

@app.patch("/api/users/me/cloudinary")
async def update_cloudinary_settings(
    request: CloudinaryUpdateRequest,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Update user's Cloudinary credentials for image uploads (encrypted storage)"""
    from app.user_database import encrypt_connection_string
    
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Encrypt sensitive credentials before storing
    encrypted_api_key = encrypt_connection_string(request.cloudinary_api_key)
    encrypted_api_secret = encrypt_connection_string(request.cloudinary_api_secret)
    
    # Update user's Cloudinary settings (cloud_name can stay plain text as it's public)
    await db.users.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$set": {
            "cloudinary_cloud_name": request.cloudinary_cloud_name,  # Plain text (public info)
            "cloudinary_api_key": encrypted_api_key,  # Encrypted
            "cloudinary_api_secret": encrypted_api_secret  # Encrypted
        }}
    )
    
    # Fetch and return updated user (with decrypted credentials for frontend use)
    updated_user = await db.users.find_one({"_id": ObjectId(current_user.id)})
    if updated_user:
        from app.user_database import decrypt_connection_string
        
        # Decrypt credentials for response
        decrypted_api_key = None
        decrypted_api_secret = None
        
        if updated_user.get("cloudinary_api_key"):
            try:
                decrypted_api_key = decrypt_connection_string(updated_user["cloudinary_api_key"])
            except:
                pass  # Handle case where old data exists
        
        if updated_user.get("cloudinary_api_secret"):
            try:
                decrypted_api_secret = decrypt_connection_string(updated_user["cloudinary_api_secret"])
            except:
                pass  # Handle case where old data exists
        
        user_response = {
            "id": str(updated_user["_id"]),
            "email": updated_user.get("email"),
            "full_name": updated_user.get("full_name"),
            "picture": updated_user.get("picture"),
            "has_database": updated_user.get("has_database", False),
            "cloudinary_cloud_name": updated_user.get("cloudinary_cloud_name"),
            "cloudinary_api_key": decrypted_api_key,  # Decrypted for frontend
            "cloudinary_api_secret": decrypted_api_secret,  # Decrypted for frontend
            "provider": updated_user.get("provider", "email")
        }
        return {
            "message": "Cloudinary settings updated successfully",
            "user": user_response
        }
    
    return {"message": "Cloudinary settings updated successfully"}

@app.post("/api/test-cloudinary", response_model=CloudinaryTestResponse)
async def test_cloudinary_credentials(request: CloudinaryTestRequest):
    """Test Cloudinary credentials without saving (server-side to avoid CORS)"""
    import httpx
    import base64
    
    try:
        # Validate cloud name format
        if not request.cloudinary_cloud_name or not request.cloudinary_cloud_name.strip():
            return CloudinaryTestResponse(success=False, message="Cloud name is required")
        
        # Check for invalid characters in cloud name
        if not all(c.isalnum() or c in '-_' for c in request.cloudinary_cloud_name):
            return CloudinaryTestResponse(
                success=False, 
                message="Cloud name can only contain letters, numbers, hyphens, and underscores (no spaces)"
            )
        
        # Test the credentials by making an API call to Cloudinary
        auth_string = f"{request.cloudinary_api_key}:{request.cloudinary_api_secret}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://api.cloudinary.com/v1_1/{request.cloudinary_cloud_name}/resources/image",
                headers={
                    "Authorization": f"Basic {encoded_auth}"
                },
                params={"max_results": 1}  # Just test, don't fetch much data
            )
            
            if response.status_code == 200:
                return CloudinaryTestResponse(
                    success=True,
                    message="Credentials verified successfully! ✓"
                )
            elif response.status_code == 401:
                return CloudinaryTestResponse(
                    success=False,
                    message="Invalid API Key or Secret. Please check your credentials."
                )
            elif response.status_code == 404:
                return CloudinaryTestResponse(
                    success=False,
                    message="Cloud name not found. Please check your Cloud Name."
                )
            else:
                return CloudinaryTestResponse(
                    success=False,
                    message=f"Cloudinary returned status {response.status_code}"
                )
                
    except httpx.TimeoutException:
        return CloudinaryTestResponse(
            success=False,
            message="Connection timeout. Please check your internet connection."
        )
    except Exception as e:
        logger.error(f"Cloudinary test error: {str(e)}")
        return CloudinaryTestResponse(
            success=False,
            message=f"Test failed: {str(e)}"
        )




# ==================== Access Control Helpers ====================

def can_view_note(note: dict, user_email: str, user_id: str) -> bool:
    """Check if user can view a note (owner or shared with)"""
    # Owner check
    if note.get("user_id") == user_id:
        return True
    # Shared with check
    shared_with = note.get("shared_with", [])
    if user_email.lower() in [email.lower() for email in shared_with]:
        return True
    return False

def can_edit_note(note: dict, user_id: str) -> bool:
    """Check if user can edit a note (only owner)"""
    return note.get("user_id") == user_id

def can_view_folder(folder: dict, user_email: str, user_id: str) -> bool:
    """Check if user can view a folder (owner or shared with)"""
    # Owner check
    if folder.get("user_id") == user_id:
        return True
    # Shared with check
    shared_with = folder.get("shared_with", [])
    if user_email.lower() in [email.lower() for email in shared_with]:
        return True
    return False

def can_edit_folder(folder: dict, user_id: str) -> bool:
    """Check if user can edit a folder (only owner)"""
    return folder.get("user_id") == user_id

# ==================== Notes Routes ====================

@app.get("/api/notes", response_model=List[NoteInDB])
async def get_all_notes(current_user: UserInDB = Depends(get_current_active_user)):
    """Get all notes (owned and shared) - shared notes are fetched live from owner's DB"""
    from app.user_database import get_user_database
    
    db = await get_user_data_db(current_user)
    main_db = get_database()
    
    if db is not None:
        all_notes = []
        
        # Get owned notes from user's personal database
        owned_notes = await db.notes.find({
            "user_id": current_user.id
        }).sort("updated_at", -1).to_list(100)
        all_notes.extend(owned_notes)
        
        logger.info(f"📝 Found {len(owned_notes)} owned notes for user {current_user.email}")
        
        # Get shared notes by looking up references in main DB
        if main_db is not None:
            try:
                # Find all notes shared with this user
                shared_refs = await main_db.shared_notes.find({
                    "shared_with_email": current_user.email.lower()
                }).to_list(100)
                
                logger.info(f"📝 Found {len(shared_refs)} shared note references for user {current_user.email}")
                
                # Group by owner to minimize DB connections
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
                        logger.warning(f"⚠️ Owner {owner_id} has no connection string")
                        continue
                    
                    try:
                        owner_db = await get_user_database(
                            owner_id,
                            owner_data["connection_string"],
                            database_name="user_data"
                        )
                        
                        # Fetch the actual notes from owner's DB
                        note_object_ids = [ObjectId(nid) for nid in owner_data["note_ids"] if ObjectId.is_valid(nid)]
                        if note_object_ids:
                            # Only fetch notes that still have current user in shared_with
                            shared_notes = await owner_db.notes.find({
                                "_id": {"$in": note_object_ids},
                                "shared_with": {"$in": [current_user.email.lower()]}
                            }).to_list(100)
                            
                            # Mark these as shared and add owner info
                            for note in shared_notes:
                                note["is_shared"] = True
                                note["shared_by"] = owner_data["owner_email"]
                                note["original_owner_id"] = owner_id
                            
                            all_notes.extend(shared_notes)
                            logger.info(f"  📝 Fetched {len(shared_notes)} shared notes from owner {owner_data['owner_email']}")

                            
                    except Exception as e:
                        logger.error(f"❌ Failed to fetch shared notes from owner {owner_id}: {e}")
                
            except Exception as e:
                logger.error(f"❌ Error fetching shared notes references: {e}")
        
        # Remove duplicates based on _id
        seen_ids = set()
        unique_notes = []
        for note in all_notes:
            note_id = str(note["_id"])
            if note_id not in seen_ids:
                seen_ids.add(note_id)
                unique_notes.append(note)
        
        # Sort by updated_at
        unique_notes.sort(key=lambda x: x.get("updated_at", datetime.min), reverse=True)
        
        owned_count = sum(1 for n in unique_notes if not n.get("is_shared"))
        shared_count = sum(1 for n in unique_notes if n.get("is_shared"))
        logger.info(f"📊 Total: {len(unique_notes)} notes (Owned: {owned_count}, Shared: {shared_count})")
        
        return [NoteInDB(**{**note, "_id": str(note["_id"])}) for note in unique_notes]
    else:
        # Fallback to in-memory storage
        return list(notes_storage.values())

@app.get("/api/notes/{note_id}", response_model=NoteInDB)
async def get_note(note_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    """Get a specific note by ID (if owned or shared)"""
    db = await get_user_data_db(current_user)
    if db is not None:
        try:
            note = await db.notes.find_one({"_id": ObjectId(note_id)})
            if note:
                # Check access
                if not can_view_note(note, current_user.email, current_user.id):
                    raise HTTPException(status_code=403, detail="You don't have permission to view this note")
                return NoteInDB(**{**note, "_id": str(note["_id"])})
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid note ID: {str(e)}")
    else:
        # Fallback to in-memory storage
        if note_id in notes_storage:
            return notes_storage[note_id]
    
    raise HTTPException(status_code=404, detail="Note not found")

# ==================== Folder Routes ====================

@app.post("/api/folders", response_model=FolderInDB)
async def create_folder(folder: FolderCreate, current_user: UserInDB = Depends(get_current_active_user)):
    """Create a new folder - inherits shares from parent if applicable"""
    db = await get_user_data_db(current_user)
    main_db = get_database()
    
    # Check for duplicate name in the same level
    existing_duplicate = await db.folders.find_one({
        "user_id": current_user.id,
        "parent_id": folder.parent_id,
        "name": folder.name
    })
    
    if existing_duplicate:
        raise HTTPException(
            status_code=400, 
            detail=f"A folder named '{folder.name}' already exists in this location"
        )
    
    folder_dict = folder.dict()
    folder_dict["user_id"] = current_user.id
    folder_dict["created_at"] = datetime.utcnow()
    
    # Inherit shared_with from parent folder
    if folder.parent_id:
        parent_folder = await db.folders.find_one({"_id": ObjectId(folder.parent_id)})
        if parent_folder and parent_folder.get("shared_with"):
            folder_dict["shared_with"] = parent_folder.get("shared_with", [])
            logger.info(f"📁 New subfolder inheriting {len(folder_dict['shared_with'])} shares from parent")
    
    new_folder = await db.folders.insert_one(folder_dict)
    created_folder = await db.folders.find_one({"_id": new_folder.inserted_id})
    folder_id = str(created_folder["_id"])
    
    # Create references in main_db.shared_folders for inherited shares
    if main_db is not None and created_folder.get("shared_with"):
        for recipient_email in created_folder.get("shared_with", []):
            await main_db.shared_folders.update_one(
                {
                    "folder_id": folder_id,
                    "owner_id": current_user.id,
                    "shared_with_email": recipient_email
                },
                {
                    "$set": {
                        "folder_id": folder_id,
                        "owner_id": current_user.id,
                        "owner_email": current_user.email.lower(),
                        "owner_connection_string": current_user.mongodb_connection_string,
                        "shared_with_email": recipient_email,
                        "folder_name": created_folder.get("name", "Untitled"),
                        "folder_parent_id": created_folder.get("parent_id"),
                        "shared_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
        logger.info(f"📁 Created {len(created_folder.get('shared_with', []))} share references for new subfolder")
    
    return FolderInDB(**{**created_folder, "_id": str(created_folder["_id"])})


@app.get("/api/folders", response_model=List[FolderInDB])
async def list_folders(current_user: UserInDB = Depends(get_current_active_user)):
    from app.user_database import get_user_database
    
    db = await get_user_data_db(current_user)
    main_db = get_database()
    all_folders = []
    
    if db is not None:
        # Get owned folders from user's personal database
        owned_folders = await db.folders.find({
            "user_id": current_user.id
        }).to_list(1000)
        all_folders.extend(owned_folders)
        
        logger.info(f"📁 Found {len(owned_folders)} owned folders for user {current_user.email}")
        
        # Get shared folders by looking up references in main DB
        if main_db is not None:
            try:
                # Find all folders shared with this user
                shared_refs = await main_db.shared_folders.find({
                    "shared_with_email": current_user.email.lower()
                }).to_list(1000)
                
                logger.info(f"📁 Found {len(shared_refs)} shared folder references for user {current_user.email}")
                
                # Group by owner to minimize DB connections
                owners_folders = {}
                for ref in shared_refs:
                    owner_id = ref.get("owner_id")
                    if owner_id not in owners_folders:
                        owners_folders[owner_id] = {
                            "connection_string": ref.get("owner_connection_string"),
                            "owner_email": ref.get("owner_email"),
                            "folder_ids": []
                        }
                    owners_folders[owner_id]["folder_ids"].append(ref.get("folder_id"))
                
                # Fetch folders from each owner's database
                for owner_id, owner_data in owners_folders.items():
                    if not owner_data["connection_string"]:
                        logger.warning(f"⚠️ Owner {owner_id} has no connection string")
                        continue
                    
                    try:
                        owner_db = await get_user_database(
                            owner_id,
                            owner_data["connection_string"],
                            database_name="user_data"
                        )
                        
                        # Fetch the actual folders from owner's DB
                        folder_object_ids = [ObjectId(fid) for fid in owner_data["folder_ids"] if ObjectId.is_valid(fid)]
                        if folder_object_ids:
                            shared_folders = await owner_db.folders.find({
                                "_id": {"$in": folder_object_ids}
                            }).to_list(1000)
                            
                            # Also fetch all child folders recursively
                            parent_folder_ids = [str(f["_id"]) for f in shared_folders]
                            child_folders = []
                            
                            # Recursive function to get all descendants that are also shared with this user
                            async def get_children(parent_ids):
                                if not parent_ids:
                                    return []
                                # Only get children that have current user in shared_with
                                children = await owner_db.folders.find({
                                    "parent_id": {"$in": parent_ids},
                                    "shared_with": {"$in": [current_user.email.lower()]}
                                }).to_list(1000)
                                if children:
                                    grandchildren = await get_children([str(c["_id"]) for c in children])
                                    return children + grandchildren
                                return []
                            
                            child_folders = await get_children(parent_folder_ids)
                            
                            # Combine parent and child folders
                            all_shared_folders = shared_folders + child_folders
                            
                            # Mark these as shared and add owner info
                            for folder in all_shared_folders:
                                folder["is_shared"] = True
                                folder["shared_by"] = owner_data["owner_email"]
                                folder["original_owner_id"] = owner_id
                            
                            all_folders.extend(all_shared_folders)
                            logger.info(f"  📁 Fetched {len(shared_folders)} parent folders + {len(child_folders)} child folders from owner {owner_data['owner_email']}")

                            
                    except Exception as e:
                        logger.error(f"❌ Failed to fetch shared folders from owner {owner_id}: {e}")

                
            except Exception as e:
                logger.error(f"❌ Error fetching shared folder references: {e}")
    
    # Remove duplicates based on _id
    seen_ids = set()
    unique_folders = []
    for folder in all_folders:
        folder_id = str(folder["_id"])
        if folder_id not in seen_ids:
            seen_ids.add(folder_id)
            unique_folders.append(folder)
    
    owned_count = sum(1 for f in unique_folders if not f.get("is_shared"))
    shared_count = sum(1 for f in unique_folders if f.get("is_shared"))
    logger.info(f"📊 Total: {len(unique_folders)} folders (Owned: {owned_count}, Shared: {shared_count})")
    
    return [FolderInDB(**{**folder, "_id": str(folder["_id"])}) for folder in unique_folders]

@app.put("/api/folders/{folder_id}", response_model=FolderInDB)
async def update_folder(folder_id: str, folder: FolderUpdate, current_user: UserInDB = Depends(get_current_active_user)):
    db = await get_user_data_db(current_user)
    
    # Check ownership
    existing_folder = await db.folders.find_one({"_id": ObjectId(folder_id)})
    if not existing_folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    
    # Check if user can edit (only owner)
    if not can_edit_folder(existing_folder, current_user.id):
        raise HTTPException(status_code=403, detail="You don't have permission to edit this folder. Only the owner can edit.")
        
    # Build update data - handle parent_id specially to allow None
    update_data = {}
    folder_dict = folder.dict(exclude_unset=True)
    
    for key, value in folder_dict.items():
        # Always include parent_id even if it's None (for moving to root)
        if key == 'parent_id':
            update_data[key] = value
        elif value is not None:
            update_data[key] = value
            
    # Check for duplicate name if name or parent_id is changing
    if "name" in update_data or "parent_id" in update_data:
        target_name = update_data.get("name", existing_folder["name"])
        target_parent_id = update_data.get("parent_id", existing_folder.get("parent_id"))
        
        # Only check if we are actually changing something relevant
        if target_name != existing_folder["name"] or target_parent_id != existing_folder.get("parent_id"):
            existing_duplicate = await db.folders.find_one({
                "user_id": current_user.id,
                "parent_id": target_parent_id,
                "name": target_name,
                "_id": {"$ne": ObjectId(folder_id)} # Exclude self
            })
            
            if existing_duplicate:
                raise HTTPException(
                    status_code=400, 
                    detail=f"A folder named '{target_name}' already exists in the destination"
                )
    
    # Check for duplicate folder name in the same parent folder (excluding self)
    if folder.name:
        # If parent_id is not provided in update, use existing parent_id
        parent_id = folder.parent_id if folder.parent_id is not None else existing_folder.get("parent_id")
        
        existing_duplicate = await db.folders.find_one({
            "user_id": current_user.id,
            "parent_id": parent_id,
            "name": folder.name,
            "_id": {"$ne": ObjectId(folder_id)}
        })
        
        if existing_duplicate:
            raise HTTPException(status_code=400, detail="A folder with this name already exists in this location")

    update_data = {k: v for k, v in folder.dict(exclude_unset=True).items()}
    update_data["updated_at"] = datetime.utcnow()
    
    await db.folders.update_one(
        {"_id": ObjectId(folder_id)},
        {"$set": update_data}
    )
        
    updated_folder = await db.folders.find_one({"_id": ObjectId(folder_id)})
    return FolderInDB(**{**updated_folder, "_id": str(updated_folder["_id"])})

@app.delete("/api/folders/{folder_id}")
async def delete_folder(
    folder_id: str, 
    background_tasks: BackgroundTasks,
    move_to_root: bool = True, 
    destination_folder_id: Optional[str] = None,
    current_user: UserInDB = Depends(get_current_active_user)
):
    db = await get_user_data_db(current_user)
    
    # Check ownership
    existing_folder = await db.folders.find_one({"_id": ObjectId(folder_id)})
    if not existing_folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    
    # Fetch user for Cloudinary credentials (needed for cleanup)
    main_db = get_database()
    user_data = await main_db.users.find_one({"_id": ObjectId(current_user.id)})
    
    # Check if user can delete (only owner)
    if not can_edit_folder(existing_folder, current_user.id):
        raise HTTPException(status_code=403, detail="You don't have permission to delete this folder. Only the owner can delete.")
    
    if move_to_root:
        # Determine where to move child items
        # If destination_folder_id is provided, use that
        # Otherwise, use the parent folder id (if exists) or None for root
        if destination_folder_id:
            target_folder_id = destination_folder_id
        else:
            target_folder_id = existing_folder.get("parent_id")
        
        # Move child folders to target destination
        await db.folders.update_many(
            {"parent_id": folder_id},
            {"$set": {"parent_id": target_folder_id}}
        )
        
        # Move notes in this folder to target destination
        await db.notes.update_many(
            {"folder_id": folder_id},
            {"$set": {"folder_id": target_folder_id}}
        )
    else:
        # Recursive delete: find all child folders
        async def delete_folder_recursive(fid):
            # Find all child folders
            child_folders = await db.folders.find({"parent_id": fid}).to_list(1000)
            
            # Recursively delete child folders
            for child in child_folders:
                await delete_folder_recursive(str(child["_id"]))
            
            # Clean up images for all notes in this folder before deleting them
            notes_in_folder = await db.notes.find({"folder_id": fid}).to_list(1000)
            for note in notes_in_folder:
                if note.get("content") and user_data:
                    background_tasks.add_task(cleanup_note_images, note["content"], user_data)
            
            # Delete all notes in this folder
            await db.notes.delete_many({"folder_id": fid})
            
            # Delete the folder itself
            await db.folders.delete_one({"_id": ObjectId(fid)})
        
        # Start recursive deletion
        await delete_folder_recursive(folder_id)
        return {"message": "Folder and all contents deleted"}
    
    await db.folders.delete_one({"_id": ObjectId(folder_id)})
    return {"message": "Folder deleted"}


@app.post("/api/folders/{folder_id}/share")
async def share_folder(
    folder_id: str,
    share_request: ShareNoteRequest,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Share a folder with another user by email - stores reference in main DB and cascades to children"""
    db = await get_user_data_db(current_user)
    main_db = get_database()
    
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Get the folder from owner's database
    try:
        folder = await db.folders.find_one({"_id": ObjectId(folder_id), "user_id": current_user.id})
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid folder ID: {str(e)}")
    
    # Normalize email
    recipient_email = share_request.email.strip().lower()
    
    # Check if recipient exists
    recipient = await get_user_by_email(recipient_email)
    is_new_user = recipient is None
    
    if is_new_user:
        logger.info(f"📧 Sharing folder with new user (no account yet): {recipient_email}")
    
    # Get all child folders recursively
    async def get_all_children(parent_id):
        """Recursively get all child folder IDs"""
        children = await db.folders.find({"parent_id": parent_id}).to_list(1000)
        all_children = children[:]
        for child in children:
            grandchildren = await get_all_children(str(child["_id"]))
            all_children.extend(grandchildren)
        return all_children
    
    child_folders = await get_all_children(folder_id)
    all_folder_ids = [folder_id] + [str(cf["_id"]) for cf in child_folders]
    
    # Get all notes in these folders
    # First, let's see all notes for this user to debug
    all_user_notes = await db.notes.find({"user_id": current_user.id}).to_list(1000)
    logger.info(f"📝 DEBUG: User has {len(all_user_notes)} total notes")
    for note in all_user_notes:
        logger.info(f"     - '{note.get('title')}' folder_id={note.get('folder_id')} (type: {type(note.get('folder_id'))})")
    
    # Notes store folder_id as strings, so we use all_folder_ids directly
    logger.info(f"📝 DEBUG: Looking for notes with folder_id in: {all_folder_ids}")
    notes_in_folders = await db.notes.find({
        "folder_id": {"$in": all_folder_ids}
    }).to_list(1000)
    
    logger.info(f"📁 Sharing folder: {folder.get('name')}")
    logger.info(f"   Folder IDs to share: {all_folder_ids}")
    logger.info(f"   Found {len(notes_in_folders)} notes in these folders")
    if notes_in_folders:
        for note in notes_in_folders:
            logger.info(f"     - Note: '{note.get('title')}' in folder {note.get('folder_id')}")
    else:
        logger.warning(f"   ⚠️  No notes found! Check if folder_id types match")
    
    logger.info(f"📁 Sharing {len(all_folder_ids)} folders (1 parent + {len(child_folders)} children) + {len(notes_in_folders)} notes")
    
    # Update all folders' shared_with list in owner's database
    await db.folders.update_many(
        {"_id": {"$in": [ObjectId(fid) for fid in all_folder_ids]}},
        {"$addToSet": {"shared_with": recipient_email}}
    )
    
    # Update all notes' shared_with list in owner's database
    if notes_in_folders:
        await db.notes.update_many(
            {"_id": {"$in": [n["_id"] for n in notes_in_folders]}},
            {"$addToSet": {"shared_with": recipient_email}}
        )
    
    # Store references in the main database for all folders
    if main_db is not None:
        for fid in all_folder_ids:
            folder_doc = await db.folders.find_one({"_id": ObjectId(fid)})
            if folder_doc:
                await main_db.shared_folders.update_one(
                    {
                        "folder_id": fid,
                        "owner_id": current_user.id,
                        "shared_with_email": recipient_email
                    },
                    {
                        "$set": {
                            "folder_id": fid,
                            "owner_id": current_user.id,
                            "owner_email": current_user.email.lower(),
                            "owner_connection_string": current_user.mongodb_connection_string,
                            "shared_with_email": recipient_email,
                            "folder_name": folder_doc.get("name", "Untitled"),
                            "folder_parent_id": folder_doc.get("parent_id"),
                            "shared_at": datetime.utcnow()
                        }
                    },
                    upsert=True
                )
        
        # Store references in main_db.shared_notes for all notes
        for note in notes_in_folders:
            note_id = str(note["_id"])
            await main_db.shared_notes.update_one(
                {
                    "note_id": note_id,
                    "owner_id": current_user.id,
                    "shared_with_email": recipient_email
                },
                {
                    "$set": {
                        "note_id": note_id,
                        "owner_id": current_user.id,
                        "owner_email": current_user.email.lower(),
                        "owner_connection_string": current_user.mongodb_connection_string,
                        "shared_with_email": recipient_email,
                        "note_title": note.get("title", "Untitled"),
                        "note_folder_id": note.get("folder_id"),
                        "shared_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
        
        logger.info(f"📁 Created {len(all_folder_ids)} folder references + {len(notes_in_folders)} note references in main DB")
    
    # Log for debugging
    logger.info(f"📧 Share Folder: {folder.get('name', 'Untitled')}")
    logger.info(f"   Owner: {current_user.email}")
    logger.info(f"   Recipient: {recipient_email}")
    logger.info(f"   Total folders shared: {len(all_folder_ids)}")
    logger.info(f"   Total notes shared: {len(notes_in_folders)}")

    
    # Send email notification in background (only for parent folder)
    background_tasks.add_task(
        send_share_notification_email,
        to_email=recipient_email,
        shared_by_name=current_user.full_name or current_user.email,
        item_type="folder",
        item_title=folder.get('name', 'Untitled')
    )
    
    return {
        "message": f"Folder, {len(child_folders)} subfolders, and {len(notes_in_folders)} notes shared with {recipient_email}",
        "is_new_user": is_new_user,
        "total_folders_shared": len(all_folder_ids),
        "total_notes_shared": len(notes_in_folders)
    }


# ==================== Notes Routes ====================

@app.post("/api/notes", response_model=NoteInDB, status_code=status.HTTP_201_CREATED)
async def create_note(note: NoteCreate, current_user: UserInDB = Depends(get_current_active_user)):
    """Create a new note - inherits shares from folder if applicable"""
    # Use user's personal DB if configured, otherwise use main DB
    db = await get_user_data_db(current_user)
    main_db = get_database()
    
    if db is not None:
        # Check for duplicate title in the same folder
        existing_duplicate = await db.notes.find_one({
            "user_id": current_user.id,
            "folder_id": note.folder_id,
            "title": note.title
        })
        
        if existing_duplicate:
            raise HTTPException(
                status_code=400,
                detail=f"A note titled '{note.title}' already exists in this location"
            )
    
    note_dict = {
        "title": note.title,
        "content": note.content,
        "folder_id": note.folder_id,  # Include folder_id from request
        "user_id": current_user.id,  # Set owner
        "shared_with": [],  # Initialize empty (will be updated if in shared folder)
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    # Inherit shared_with from folder if note is created in a folder
    if note.folder_id and db is not None:
        parent_folder = await db.folders.find_one({"_id": ObjectId(note.folder_id)})
        if parent_folder and parent_folder.get("shared_with"):
            note_dict["shared_with"] = parent_folder.get("shared_with", [])
            logger.info(f"📝 New note inheriting {len(note_dict['shared_with'])} shares from folder")
    
    if db is not None:
        result = await db.notes.insert_one(note_dict)
        created_note = await db.notes.find_one({"_id": result.inserted_id})
        note_id = str(created_note["_id"])
        
        # Create references in main_db.shared_notes for inherited shares
        if main_db is not None:
            if created_note.get("shared_with"):
                for recipient_email in created_note.get("shared_with", []):
                    await main_db.shared_notes.update_one(
                        {
                            "note_id": note_id,
                            "owner_id": current_user.id,
                            "shared_with_email": recipient_email
                        },
                        {
                            "$set": {
                                "note_id": note_id,
                                "owner_id": current_user.id,
                                "owner_email": current_user.email.lower(),
                                "owner_connection_string": current_user.mongodb_connection_string,
                                "shared_with_email": recipient_email,
                                "note_title": created_note.get("title", "Untitled"),
                                "note_folder_id": created_note.get("folder_id"),
                                "shared_at": datetime.utcnow()
                            }
                        },
                        upsert=True
                    )
                logger.info(f"📝 Created {len(created_note.get('shared_with', []))} share references for new note")
            
            # Increment user's note count in MAIN database (not user's DB)
            await main_db.users.update_one(
                {"_id": ObjectId(current_user.id)},
                {"$inc": {"notes_count": 1}}
            )
        
        return NoteInDB(**{**created_note, "_id": str(created_note["_id"])})
    else:
        # Fallback to in-memory storage
        note_id = str(ObjectId())
        note_dict["_id"] = note_id
        new_note = NoteInDB(**note_dict)
        notes_storage[note_id] = new_note
        return new_note

@app.put("/api/notes/{note_id}", response_model=NoteInDB)
async def update_note(note_id: str, note_update: NoteUpdate, current_user: UserInDB = Depends(get_current_active_user)):
    """Update a note (only owner can edit)"""
    db = await get_user_data_db(current_user)
    
    # Build update data - handle folder_id specially to allow None
    update_data = {}
    note_dict = note_update.dict(exclude_unset=True)
    
    for key, value in note_dict.items():
        # Always include folder_id even if it's None (for moving to root)
        if key == 'folder_id':
            update_data[key] = value
        elif value is not None:
            update_data[key] = value
    
    update_data["updated_at"] = datetime.utcnow()
    
    if db is not None:
        try:
            # First check if note exists and user has edit permission
            note = await db.notes.find_one({"_id": ObjectId(note_id)})
            if not note:
                raise HTTPException(status_code=404, detail="Note not found")
            
            # Check if user can edit (only owner)
            if not can_edit_note(note, current_user.id):
                raise HTTPException(status_code=403, detail="You don't have permission to edit this note. Only the owner can edit.")
            
            # Check for duplicate title if title or folder_id is changing
            if "title" in update_data or "folder_id" in update_data:
                target_title = update_data.get("title", note.get("title"))
                target_folder_id = update_data.get("folder_id", note.get("folder_id"))
                
                # Only check if we are actually changing something relevant
                if target_title != note.get("title") or target_folder_id != note.get("folder_id"):
                    existing_duplicate = await db.notes.find_one({
                        "user_id": current_user.id,
                        "folder_id": target_folder_id,
                        "title": target_title,
                        "_id": {"$ne": ObjectId(note_id)}  # Exclude self
                    })
                    
                    if existing_duplicate:
                        raise HTTPException(
                            status_code=400,
                            detail=f"A note titled '{target_title}' already exists in this location"
                        )
            
            result = await db.notes.find_one_and_update(
                {"_id": ObjectId(note_id)},
                {"$set": update_data},
                return_document=True
            )
            if result:
                return NoteInDB(**{**result, "_id": str(result["_id"])})
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid note ID: {str(e)}")
    else:
        # Fallback to in-memory storage
        if note_id in notes_storage:
            current_note = notes_storage[note_id]
            for key, value in update_data.items():
                setattr(current_note, key, value)
            return current_note
    
    raise HTTPException(status_code=404, detail="Note not found")

@app.delete("/api/notes/{note_id}")
async def delete_note(
    note_id: str, 
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Delete a note (only owner can delete)"""
    db = await get_user_data_db(current_user)
    if db is not None:
        try:
            # First check if note exists and user has delete permission
            note = await db.notes.find_one({"_id": ObjectId(note_id)})
            if not note:
                raise HTTPException(status_code=404, detail="Note not found")
            
            # Check if user can edit (only owner)
            if not can_edit_note(note, current_user.id):
                raise HTTPException(status_code=403, detail="You don't have permission to delete this note. Only the owner can delete.")
            
            # Fetch user for Cloudinary credentials
            main_db = get_database()
            user_data = await main_db.users.find_one({"_id": ObjectId(current_user.id)})
            
            # Trigger background cleanup for images
            if note.get("content") and user_data:
                background_tasks.add_task(cleanup_note_images, note["content"], user_data)
            
            result = await db.notes.delete_one({"_id": ObjectId(note_id)})
            if result.deleted_count:
                # Decrement user's note count in MAIN database
                if main_db is not None:
                    await main_db.users.update_one(
                        {"_id": ObjectId(current_user.id)},
                        {"$inc": {"notes_count": -1}}
                    )
                return {"message": "Note deleted successfully"}

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid note ID: {str(e)}")
    else:
        # Fallback to in-memory storage
        if note_id in notes_storage:
            del notes_storage[note_id]
            return {"message": "Note deleted successfully"}
    
    raise HTTPException(status_code=404, detail="Note not found")

@app.post("/api/notes/{note_id}/share")
async def share_note(
    note_id: str, 
    share_request: ShareNoteRequest,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Share a note with another user by email - stores reference in main DB"""
    db = await get_user_data_db(current_user)
    main_db = get_database()
    
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Get the note from owner's database
    try:
        note = await db.notes.find_one({"_id": ObjectId(note_id)})
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid note ID: {str(e)}")
    
    # Normalize email
    recipient_email = share_request.email.strip().lower()
    
    # Check if recipient exists
    recipient = await get_user_by_email(recipient_email)
    is_new_user = recipient is None
    
    if is_new_user:
        logger.info(f"📧 Sharing with new user (no account yet): {recipient_email}")
    
    # Update note's shared_with list and share_history in owner's database
    share_record = {
        "email": recipient_email,
        "shared_at": datetime.utcnow(),
        "recipient_user_id": recipient.id if recipient else None
    }
    
    await db.notes.update_one(
        {"_id": ObjectId(note_id)},
        {
            "$addToSet": {"shared_with": recipient_email},
            "$push": {"share_history": share_record}
        }
    )
    
    # Store a reference in the main database's shared_notes collection
    # This allows recipients to discover shared notes and fetch from owner's DB
    if main_db is not None:
        await main_db.shared_notes.update_one(
            {
                "note_id": note_id,
                "owner_id": current_user.id,
                "shared_with_email": recipient_email
            },
            {
                "$set": {
                    "note_id": note_id,
                    "owner_id": current_user.id,
                    "owner_email": current_user.email.lower(),
                    "owner_connection_string": current_user.mongodb_connection_string,
                    "shared_with_email": recipient_email,
                    "note_title": note.get("title", "Untitled"),
                    "note_folder_id": note.get("folder_id"),
                    "shared_at": datetime.utcnow()
                }
            },
            upsert=True
        )
        logger.info(f"📝 Created shared_notes reference in main DB for recipient: {recipient_email}")
    
    # Log for debugging
    logger.info(f"📧 Share Note: {note.get('title', 'Untitled')}")
    logger.info(f"   Owner: {current_user.email}")
    logger.info(f"   Recipient: {recipient_email}")
    
    # Send email notification in background
    background_tasks.add_task(
        send_share_notification_email,
        to_email=recipient_email,
        shared_by_name=current_user.full_name or current_user.email,
        item_type="note",
        item_title=note.get('title', 'Untitled')
    )
    
    return {
        "message": f"Note shared with {recipient_email}",
        "is_new_user": is_new_user
    }


@app.get("/api/notes/{note_id}/shares")
async def get_note_shares(
    note_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Get list of users the note is shared with (for owner's share page)"""
    db = await get_user_data_db(current_user)
    
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        note = await db.notes.find_one({"_id": ObjectId(note_id)})
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        
        # Only owner can see share list
        if note.get("user_id") != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can view share details")
        
        shared_with = note.get("shared_with", [])
        share_history = note.get("share_history", [])
        
        # Build response with user details
        shares = []
        for email in shared_with:
            user = await get_user_by_email(email)
            # Find the latest share record for this email
            latest_share = None
            for record in reversed(share_history):
                if record.get("email") == email:
                    latest_share = record
                    break
            
            shares.append({
                "email": email,
                "full_name": user.full_name if user else None,
                "picture": user.picture if user else None,
                "has_account": user is not None,
                "shared_at": latest_share.get("shared_at") if latest_share else None
            })
        
        return {
            "note_id": note_id,
            "note_title": note.get("title", "Untitled"),
            "shares": shares,
            "total_shares": len(shares)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.post("/api/notes/{note_id}/shares/{email}/resend")
async def resend_share_notification(
    note_id: str,
    email: str,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Resend share notification email to a recipient"""
    db = await get_user_data_db(current_user)
    
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        note = await db.notes.find_one({"_id": ObjectId(note_id)})
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        
        # Only owner can resend
        if note.get("user_id") != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can resend share notifications")
        
        # Check if email is in shared_with list
        recipient_email = email.strip().lower()
        if recipient_email not in note.get("shared_with", []):
            raise HTTPException(status_code=400, detail="This note is not shared with that email")
        
        # Send email notification in background
        background_tasks.add_task(
            send_share_notification_email,
            to_email=recipient_email,
            shared_by_name=current_user.full_name or current_user.email,
            item_type="note",
            item_title=note.get('title', 'Untitled')
        )
        
        logger.info(f"📧 Resent share notification for '{note.get('title')}' to {recipient_email}")
        
        return {"message": f"Share notification resent to {recipient_email}"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.delete("/api/notes/{note_id}/shares/{email}")
async def unshare_note(
    note_id: str,
    email: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Remove sharing access for a user"""
    db = await get_user_data_db(current_user)
    main_db = get_database()
    
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        note = await db.notes.find_one({"_id": ObjectId(note_id)})
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        
        # Only owner can unshare
        if note.get("user_id") != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can remove sharing")
        
        recipient_email = email.strip().lower()
        
        # Remove from shared_with list in owner's DB
        await db.notes.update_one(
            {"_id": ObjectId(note_id)},
            {"$pull": {"shared_with": recipient_email}}
        )
        
        # Remove the shared_notes reference from main DB
        if main_db is not None:
            result = await main_db.shared_notes.delete_one({
                "note_id": note_id,
                "owner_id": current_user.id,
                "shared_with_email": recipient_email
            })
            logger.info(f"🗑️ Removed shared_notes reference from main DB (deleted: {result.deleted_count})")
        
        logger.info(f"📧 Unshared note '{note.get('title')}' from {recipient_email}")
        
        return {"message": f"Sharing removed for {recipient_email}"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.get("/api/folders/{folder_id}/shares")
async def get_folder_shares(
    folder_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Get list of users the folder is shared with (for owner's share page)"""
    db = await get_user_data_db(current_user)
    
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        folder = await db.folders.find_one({"_id": ObjectId(folder_id)})
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")
        
        # Only owner can see share list
        if folder.get("user_id") != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can view share details")
        
        shared_with = folder.get("shared_with", [])
        
        # Build response with user details
        shares = []
        for email in shared_with:
            user = await get_user_by_email(email)
            
            shares.append({
                "email": email,
                "full_name": user.full_name if user else None,
                "picture": user.picture if user else None,
                "has_account": user is not None,
                "shared_at": folder.get("created_at")  # Folders don't have share_history yet
            })
        
        return {
            "folder_id": folder_id,
            "folder_name": folder.get("name", "Untitled"),
            "shares": shares,
            "total_shares": len(shares)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.post("/api/folders/{folder_id}/shares/{email}/resend")
async def resend_folder_share_notification(
    folder_id: str,
    email: str,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Resend share notification email to a recipient"""
    db = await get_user_data_db(current_user)
    
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        folder = await db.folders.find_one({"_id": ObjectId(folder_id)})
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")
        
        # Only owner can resend
        if folder.get("user_id") != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can resend share notifications")
        
        # Check if email is in shared_with list
        recipient_email = email.strip().lower()
        if recipient_email not in folder.get("shared_with", []):
            raise HTTPException(status_code=400, detail="This folder is not shared with that email")
        
        # Send email notification in background
        background_tasks.add_task(
            send_share_notification_email,
            to_email=recipient_email,
            shared_by_name=current_user.full_name or current_user.email,
            item_type="folder",
            item_title=folder.get('name', 'Untitled')
        )
        
        logger.info(f"📧 Resent share notification for folder '{folder.get('name')}' to {recipient_email}")
        
        return {"message": f"Share notification resent to {recipient_email}"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")


@app.delete("/api/folders/{folder_id}/shares/{email}")
async def unshare_folder(
    folder_id: str,
    email: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Remove sharing access for a user - cascades to all child folders"""
    db = await get_user_data_db(current_user)
    main_db = get_database()
    
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        folder = await db.folders.find_one({"_id": ObjectId(folder_id)})
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")
        
        # Only owner can unshare
        if folder.get("user_id") != current_user.id:
            raise HTTPException(status_code=403, detail="Only the owner can remove sharing")
        
        recipient_email = email.strip().lower()
        
        # Get all child folders recursively
        async def get_all_children(parent_id):
            """Recursively get all child folder IDs"""
            children = await db.folders.find({"parent_id": parent_id}).to_list(1000)
            all_children = children[:]
            for child in children:
                grandchildren = await get_all_children(str(child["_id"]))
                all_children.extend(grandchildren)
            return all_children
        
        child_folders = await get_all_children(folder_id)
        all_folder_ids = [folder_id] + [str(cf["_id"]) for cf in child_folders]
        
        # Get all notes in these folders
        notes_in_folders = await db.notes.find({
            "folder_id": {"$in": all_folder_ids}
        }).to_list(1000)
        note_ids = [str(n["_id"]) for n in notes_in_folders]
        
        logger.info(f"🗑️ Unsharing {len(all_folder_ids)} folders (1 parent + {len(child_folders)} children) + {len(notes_in_folders)} notes")
        
        # Remove from shared_with array in owner's database for all folders
        await db.folders.update_many(
            {"_id": {"$in": [ObjectId(fid) for fid in all_folder_ids]}},
            {"$pull": {"shared_with": recipient_email}}
        )
        
        # Remove from shared_with array in owner's database for all notes
        if notes_in_folders:
            await db.notes.update_many(
                {"_id": {"$in": [ObjectId(nid) for nid in note_ids]}},
                {"$pull": {"shared_with": recipient_email}}
            )
        
        # Remove all references from main database
        if main_db is not None:
            folder_result = await main_db.shared_folders.delete_many({
                "folder_id": {"$in": all_folder_ids},
                "owner_id": current_user.id,
                "shared_with_email": recipient_email
            })
            
            note_result = await main_db.shared_notes.delete_many({
                "note_id": {"$in": note_ids},
                "owner_id": current_user.id,
                "shared_with_email": recipient_email
            })
            
            logger.info(f"🗑️ Removed {folder_result.deleted_count} folder references + {note_result.deleted_count} note references from main DB")
        
        logger.info(f"🗑️ Unshared folder '{folder.get('name')}', {len(child_folders)} children, and {len(notes_in_folders)} notes with {recipient_email}")
        
        return {
            "message": f"Folder, {len(child_folders)} subfolders, and {len(notes_in_folders)} notes no longer shared with {recipient_email}",
            "total_folders_unshared": len(all_folder_ids),
            "total_notes_unshared": len(notes_in_folders)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {str(e)}")




# ==================== AI Assistant Routes ====================

@app.post("/api/ai/chat", response_model=AIResponse)
async def ai_chat(request: AIRequest, current_user: UserInDB = Depends(get_current_active_user)):
    """AI assistant endpoint using user-configured LLM provider from Settings"""
    import os
    
    # Use user's data database (which might be their personal MongoDB)
    db = await get_user_data_db(current_user)
    if db is None:
        return AIResponse(
            message="Database not available. Please try again later.",
            updated_content=None
        )
    
    # Get user's LLM settings from database
    settings_doc = await db.llm_settings.find_one({"user_id": current_user.id})
    
    # Debug logging
    logger.info(f"👤 User: {current_user.id}")
    logger.info(f"📂 Settings Doc Found: {settings_doc is not None}")
    if settings_doc:
        logger.info(f"📋 Providers in DB: {len(settings_doc.get('providers', []))}")
        logger.info(f"📄 Full Settings: {settings_doc}")
    
    if not settings_doc or "providers" not in settings_doc or not settings_doc["providers"]:
        reason = "Settings document or providers list is missing in DB"
        logger.error(f"❌ AI Chat Error: {reason}")
        return AIResponse(
            message="AI assistant is not configured. Please add an LLM provider in Settings (⚙️ icon).",
            updated_content=None
        )
    
    # Get active providers
    providers = settings_doc.get("providers", [])
    # Log available providers
    logger.info(f"🔍 All providers: {len(providers)}")
    for i, p in enumerate(providers):
        logger.info(f"  Provider {i}: {p.get('name')} - Active: {p.get('is_active')} - Model: {p.get('model')}")
    
    active_providers = [p for p in providers if p.get("is_active")]
    logger.info(f"✅ Active providers: {len(active_providers)}")
    
    # Fallback: If providers exist but none are active, use the first one
    if not active_providers and providers:
        logger.warning("⚠️ No active providers found, falling back to first available provider")
        active_providers = [providers[0]]
    
    if not active_providers:
        return AIResponse(
            message="No active LLM providers found. Please enable a provider in Settings.",
            updated_content=None
        )
    
    # Use default model if set, otherwise use first active provider
    default_model = settings_doc.get("default_model")
    selected_provider = None
    
    if default_model:
        selected_provider = next((p for p in active_providers if p.get("name") == default_model), None)
    
    if not selected_provider:
        selected_provider = active_providers[0]
    
    api_key = selected_provider.get("api_key")
    provider_type = selected_provider.get("provider", "openrouter")
    model = selected_provider.get("model")
    
    if not model:
        return AIResponse(
            message=f"Model not configured for '{selected_provider.get('name')}'. Please update it in Settings.",
            updated_content=None
        )
    
    if not api_key:
        return AIResponse(
            message=f"API key not configured for '{selected_provider.get('name')}'. Please add it in Settings.",
            updated_content=None
        )
    
    try:
        # Get system prompt with priority:
        # 1. Use global prompt if provider has use_global_prompt=True
        # 2. Provider-specific prompt
        # 3. Global prompt (if no provider prompt)
        # 4. Default prompt (fallback)
        
        use_global = selected_provider.get("use_global_prompt", False)
        provider_system_prompt = (selected_provider.get("system_prompt") or "").strip()
        global_system_prompt = (settings_doc.get("system_prompt") or "").strip()
        
        # Default system prompt based on edit mode
        if request.edit_mode:
            system_prompt = """You are a helpful AI assistant that edits note documents.

IMPORTANT: Your response will REPLACE the entire note content. You MUST return the complete, updated note including:
- All existing content that should be kept
- Your edits/changes applied
- Proper markdown formatting

User requests may ask you to:
- Improve/rewrite specific sections
- Fix grammar and spelling throughout
- Add or remove content
- Reorganize or restructure
- Change tone or style

ALWAYS return the FULL note content with your modifications applied, not just the changed parts.
Use proper markdown formatting (headings, lists, bold, italic, etc.)."""
        else:
            system_prompt = DEFAULT_SYSTEM_PROMPT
        
        # Override with custom prompt if explicitly enabled
        if use_global and global_system_prompt:
            # Provider explicitly wants to use global prompt
            system_prompt = global_system_prompt
        elif provider_system_prompt:
            # Use provider-specific system prompt
            system_prompt = provider_system_prompt
        
        # Prepare messages
        messages = [
            {"role": "system", "content": system_prompt},
        ]
        
        logger.info(f"🔧 AI Chat Debug:")
        logger.info(f"  Provider: {provider_type}")
        logger.info(f"  Model: {model}")
        logger.info(f"  System Prompt Length: {len(system_prompt)} chars")
        logger.info(f"  System Prompt Preview: {system_prompt[:100]}...")
        
        # Add context about the current note if there is content
        if request.current_content:
            messages.append({
                "role": "system",
                "content": f"Current note content:\n\n{request.current_content}"
            })
        
        # Add context about user's existing structure
        folders_data = await db.folders.find({"user_id": current_user.id}).to_list(length=100)
        notes_data = await db.notes.find({"user_id": current_user.id}, {"title": 1, "folder_id": 1}).to_list(length=200)
        
        # Build structure summary (Hierarchical)
        def build_tree_text(parent_id=None, level=0):
            text = ""
            indent = "  " * level
            
            # Add folders at this level
            level_folders = [f for f in folders_data if f.get("parent_id") == parent_id]
            for f in level_folders:
                text += f"{indent}📂 Folder: {f.get('name')}\n"
                # Add notes in this folder
                folder_notes = [n for n in notes_data if str(n.get("folder_id")) == str(f.get("_id"))]
                for n in folder_notes:
                    text += f"{indent}  📄 Note: {n.get('title')}\n"
                # Recursively add subfolders
                text += build_tree_text(str(f.get("_id")), level + 1)
            
            # Root level special case: Add root notes
            if parent_id is None:
                root_notes = [n for n in notes_data if not n.get("folder_id")]
                for n in root_notes:
                    text += f"📄 Note: {n.get('title')}\n"
            
            return text

        structure_text = build_tree_text()
        structure_summary = "CRITICAL_CONTEXT: CURRENT_STRUCTURE\n" + (structure_text if structure_text.strip() else "(No folders or notes exist yet)\n")

        messages.append({
            "role": "system",
            "content": structure_summary
        })

        # Add chat history if provided
        if request.messages:
            for msg in request.messages:
                # Filter out messages that might have been processed/filtered on frontend
                # and ensure we only send role/content
                if "role" in msg and "content" in msg:
                    messages.append({
                        "role": msg["role"],
                        "content": msg["content"]
                    })
        else:
            # If no history provided, just add the current user message
            messages.append({
                "role": "user",
                "content": request.message
            })

        
        logger.info(f"  User Message: {request.message}")
        logger.info(f"  Total Messages: {len(messages)}")
        
        # Determine API endpoint and headers based on provider
        url = ""
        headers = {}
        payload = {}
        
        if provider_type == "openai":
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.7
            }
        elif provider_type == "anthropic":
            url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            # Anthropic expects system prompt separately
            system_content = next((m["content"] for m in messages if m["role"] == "system"), "")
            user_messages = [m for m in messages if m["role"] != "system"]
            payload = {
                "model": model,
                "messages": user_messages,
                "system": system_content,
                "max_tokens": 2000
            }
        elif provider_type == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            headers = {"Content-Type": "application/json"}
            # Gemini format conversion
            gemini_contents = []
            system_instruction = None
            
            for msg in messages:
                if msg["role"] == "system":
                    system_instruction = {"parts": [{"text": msg["content"]}]}
                else:
                    role = "user" if msg["role"] == "user" else "model"
                    gemini_contents.append({
                        "role": role,
                        "parts": [{"text": msg["content"]}]
                    })
            
            payload = {
                "contents": gemini_contents,
                "generationConfig": {"temperature": 0.7}
            }
            if system_instruction:
                payload["systemInstruction"] = system_instruction
        elif provider_type == "ollama":
            # Ollama API - api_key is actually the base URL (e.g., http://localhost:11434)
            url = f"{api_key}/api/chat"
            headers = {"Content-Type": "application/json"}
            payload = {
                "model": model,
                "messages": messages,
                "stream": False
            }
        else:
            # Default to OpenRouter
            url = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://mindflow.ai", 
                "X-Title": "MindFlow AI"
            }
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 2000  # Reduced to prevent credit issues
            }

        # Make API call
        logger.info(f"  🌐 Calling API: {url}")
        logger.info(f"  📦 Payload model: {payload.get('model', 'N/A')}")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers=headers,
                json=payload,
                timeout=60.0
            )
            
            logger.info(f"  ✅ Response Status: {response.status_code}")
            
            if response.status_code != 200:
                error_detail = response.text
                logger.error(f"❌ LLM API Error ({provider_type}): {response.status_code} - {error_detail}")
                
                # Parse error for user-friendly message
                user_message = "AI service error. Please try again."
                try:
                    error_json = response.json()
                    if "error" in error_json and isinstance(error_json["error"], dict):
                        if "message" in error_json["error"]:
                            error_msg = error_json["error"]["message"]
                            if response.status_code == 402 or "credits" in error_msg.lower():
                                user_message = "⚠️ Insufficient credits. Please add credits to your AI provider or switch providers in Settings."
                            elif "rate limit" in error_msg.lower():
                                user_message = "⚠️ Rate limit exceeded. Please wait and try again."
                            else:
                                user_message = f"⚠️ {error_msg[:150]}"
                except:
                    pass
                
                raise HTTPException(status_code=response.status_code, detail=user_message)
            
            result = response.json()
            logger.info(f"  📄 Response Keys: {list(result.keys())}")
            
            # Extract content based on provider
            if provider_type == "anthropic":
                ai_message = result["content"][0]["text"]
            elif provider_type == "gemini":
                ai_message = result["candidates"][0]["content"]["parts"][0]["text"]
            elif provider_type == "ollama":
                # Ollama format
                ai_message = result["message"]["content"]
            else:
                # OpenAI / OpenRouter format
                ai_message = result["choices"][0]["message"]["content"]
            
            logger.info(f"  💬 AI Message Length: {len(ai_message)} chars")
            logger.info(f"  💬 AI Message Preview: {ai_message[:200] if ai_message else 'EMPTY!'}")
        
        # If edit mode is enabled, use AI response as the updated content
        updated_content = None
        if request.edit_mode:
            # AI has been instructed to provide complete document
            updated_content = ai_message
        
        return AIResponse(message=ai_message, updated_content=updated_content)
    
    except Exception as e:
        logger.error(f"AI Chat Error: {str(e)}")
        # Return a friendly error message
        return AIResponse(
            message=f"Sorry, I encountered an error: {str(e)}. Please try again.",
            updated_content=None
        )


@app.post("/api/ai/chat/stream")
async def ai_chat_stream(request: AIRequest, current_user: UserInDB = Depends(get_current_active_user)):
    """Streaming AI assistant endpoint using Server-Sent Events (SSE)"""
    import os
    
    # Use user's data database
    db = await get_user_data_db(current_user)
    if db is None:
        async def error_stream():
            yield f"data: {json.dumps({'error': 'Database not available'})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")
    
    # Get user's LLM settings
    settings_doc = await db.llm_settings.find_one({"user_id": current_user.id})
    
    if not settings_doc or "providers" not in settings_doc or not settings_doc["providers"]:
        async def error_stream():
            yield f"data: {json.dumps({'error': 'AI assistant is not configured. Please add an LLM provider in Settings.'})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")
    
    # Get active providers
    providers = settings_doc.get("providers", [])
    active_providers = [p for p in providers if p.get("is_active")]
    
    if not active_providers and providers:
        active_providers = [providers[0]]
    
    if not active_providers:
        async def error_stream():
            yield f"data: {json.dumps({'error': 'No active LLM providers found.'})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")
    
    # Select provider
    default_model = settings_doc.get("default_model")
    selected_provider = None
    if default_model:
        selected_provider = next((p for p in active_providers if p.get("name") == default_model), None)
    if not selected_provider:
        selected_provider = active_providers[0]
    
    api_key = selected_provider.get("api_key")
    provider_type = selected_provider.get("provider", "openrouter")
    model = selected_provider.get("model")
    
    if not model or not api_key:
        async def error_stream():
            yield f"data: {json.dumps({'error': 'Model or API key not configured.'})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")
    
    # Build system prompt
    use_global = selected_provider.get("use_global_prompt", False)
    provider_system_prompt = (selected_provider.get("system_prompt") or "").strip()
    global_system_prompt = (settings_doc.get("system_prompt") or "").strip()
    
    if request.edit_mode:
        system_prompt = """You are a helpful AI assistant that edits note documents.

IMPORTANT: Your response will REPLACE the entire note content. You MUST return the complete, updated note including:
- All existing content that should be kept
- Your edits/changes applied
- Proper markdown formatting

User requests may ask you to:
- Improve/rewrite specific sections
- Fix grammar and spelling throughout
- Add or remove content
- Reorganize or restructure
- Change tone or style

ALWAYS return the FULL note content with your modifications applied, not just the changed parts.
Use proper markdown formatting (headings, lists, bold, italic, etc.)."""
    else:
        system_prompt = DEFAULT_SYSTEM_PROMPT
    
    if use_global and global_system_prompt:
        system_prompt = global_system_prompt
    elif provider_system_prompt:
        system_prompt = provider_system_prompt
    
    # Prepare messages
    messages = [{"role": "system", "content": system_prompt}]
    
    if request.current_content:
        messages.append({
            "role": "system",
            "content": f"Current note content:\n\n{request.current_content}"
        })
    
    # Add folder structure context
    folders_data = await db.folders.find({"user_id": current_user.id}).to_list(length=100)
    notes_data = await db.notes.find({"user_id": current_user.id}, {"title": 1, "folder_id": 1}).to_list(length=200)
    
    def build_tree_text(parent_id=None, level=0):
        text = ""
        indent = "  " * level
        level_folders = [f for f in folders_data if f.get("parent_id") == parent_id]
        for f in level_folders:
            text += f"{indent}📂 Folder: {f.get('name')}\n"
            folder_notes = [n for n in notes_data if str(n.get("folder_id")) == str(f.get("_id"))]
            for n in folder_notes:
                text += f"{indent}  📄 Note: {n.get('title')}\n"
            text += build_tree_text(str(f.get("_id")), level + 1)
        if parent_id is None:
            root_notes = [n for n in notes_data if not n.get("folder_id")]
            for n in root_notes:
                text += f"📄 Note: {n.get('title')}\n"
        return text

    structure_text = build_tree_text()
    structure_summary = "CRITICAL_CONTEXT: CURRENT_STRUCTURE\n" + (structure_text if structure_text.strip() else "(No folders or notes exist yet)\n")
    messages.append({"role": "system", "content": structure_summary})
    
    # Add chat history
    if request.messages:
        for msg in request.messages:
            if "role" in msg and "content" in msg:
                messages.append({"role": msg["role"], "content": msg["content"]})
    else:
        messages.append({"role": "user", "content": request.message})
    
    async def stream_response():
        try:
            async with httpx.AsyncClient() as client:
                if provider_type == "openai":
                    url = "https://api.openai.com/v1/chat/completions"
                    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                    payload = {"model": model, "messages": messages, "temperature": 0.7, "stream": True}
                    
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line.startswith("data: "):
                                data = line[6:]
                                if data == "[DONE]":
                                    yield "data: [DONE]\n\n"
                                    break
                                try:
                                    chunk = json.loads(data)
                                    if chunk.get("choices") and chunk["choices"][0].get("delta", {}).get("content"):
                                        content = chunk["choices"][0]["delta"]["content"]
                                        yield f"data: {json.dumps({'content': content})}\n\n"
                                except json.JSONDecodeError:
                                    pass
                
                elif provider_type == "anthropic":
                    url = "https://api.anthropic.com/v1/messages"
                    headers = {
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json"
                    }
                    system_content = "\n\n".join([m["content"] for m in messages if m["role"] == "system"])
                    user_messages = [m for m in messages if m["role"] != "system"]
                    payload = {
                        "model": model,
                        "messages": user_messages,
                        "system": system_content,
                        "max_tokens": 2000,
                        "stream": True
                    }
                    
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line.startswith("data: "):
                                data = line[6:]
                                try:
                                    chunk = json.loads(data)
                                    if chunk.get("type") == "content_block_delta":
                                        content = chunk.get("delta", {}).get("text", "")
                                        if content:
                                            yield f"data: {json.dumps({'content': content})}\n\n"
                                    elif chunk.get("type") == "message_stop":
                                        yield "data: [DONE]\n\n"
                                except json.JSONDecodeError:
                                    pass
                
                elif provider_type == "gemini":
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent?alt=sse&key={api_key}"
                    headers = {"Content-Type": "application/json"}
                    gemini_contents = []
                    system_instruction = None
                    for msg in messages:
                        if msg["role"] == "system":
                            system_instruction = {"parts": [{"text": msg["content"]}]}
                        else:
                            role = "user" if msg["role"] == "user" else "model"
                            gemini_contents.append({"role": role, "parts": [{"text": msg["content"]}]})
                    payload = {"contents": gemini_contents, "generationConfig": {"temperature": 0.7}}
                    if system_instruction:
                        payload["systemInstruction"] = system_instruction
                    
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line.startswith("data: "):
                                data = line[6:]
                                try:
                                    chunk = json.loads(data)
                                    if chunk.get("candidates"):
                                        parts = chunk["candidates"][0].get("content", {}).get("parts", [])
                                        for part in parts:
                                            if part.get("text"):
                                                yield f"data: {json.dumps({'content': part['text']})}\n\n"
                                except json.JSONDecodeError:
                                    pass
                    yield "data: [DONE]\n\n"
                
                elif provider_type == "ollama":
                    url = f"{api_key}/api/chat"
                    headers = {"Content-Type": "application/json"}
                    payload = {"model": model, "messages": messages, "stream": True}
                    
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line:
                                try:
                                    chunk = json.loads(line)
                                    if chunk.get("message", {}).get("content"):
                                        content = chunk["message"]["content"]
                                        yield f"data: {json.dumps({'content': content})}\n\n"
                                    if chunk.get("done"):
                                        yield "data: [DONE]\n\n"
                                except json.JSONDecodeError:
                                    pass
                
                else:  # OpenRouter
                    url = "https://openrouter.ai/api/v1/chat/completions"
                    headers = {
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://mindflow.ai",
                        "X-Title": "MindFlow AI"
                    }
                    payload = {"model": model, "messages": messages, "temperature": 0.7, "max_tokens": 2000, "stream": True}
                    
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line.startswith("data: "):
                                data = line[6:]
                                if data == "[DONE]":
                                    yield "data: [DONE]\n\n"
                                    break
                                try:
                                    chunk = json.loads(data)
                                    if chunk.get("choices") and chunk["choices"][0].get("delta", {}).get("content"):
                                        content = chunk["choices"][0]["delta"]["content"]
                                        yield f"data: {json.dumps({'content': content})}\n\n"
                                except json.JSONDecodeError:
                                    pass
        
        except Exception as e:
            logger.error(f"Streaming error: {str(e)}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: [DONE]\n\n"
    
    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

# ==================== Chat History Routes ====================

@app.get("/api/chats", response_model=List[ChatInDB])
async def get_chats(current_user: UserInDB = Depends(get_current_active_user)):
    """Get all chats for the current user"""
    db = await get_user_data_db(current_user)
    if db is not None:
        chats = await db.chats.find({"user_id": current_user.id}).sort("updated_at", -1).to_list(100)
        return [ChatInDB(**{**chat, "_id": str(chat["_id"])}) for chat in chats]
    return []

@app.get("/api/chats/{chat_id}", response_model=ChatInDB)
async def get_chat(chat_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    """Get a specific chat by ID"""
    db = await get_user_data_db(current_user)
    if db is not None:
        try:
            chat = await db.chats.find_one({"_id": ObjectId(chat_id), "user_id": current_user.id})
            if chat:
                return ChatInDB(**{**chat, "_id": str(chat["_id"])})
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid chat ID: {str(e)}")
    raise HTTPException(status_code=404, detail="Chat not found")

@app.post("/api/chats", response_model=ChatInDB, status_code=status.HTTP_201_CREATED)
async def create_chat(chat: ChatCreate, current_user: UserInDB = Depends(get_current_active_user)):
    """Create a new chat"""
    db = await get_user_data_db(current_user)
    chat_dict = {
        "title": chat.title,
        "messages": [msg.dict() for msg in chat.messages],
        "note_id": chat.note_id,
        "user_id": current_user.id, # Add user_id
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    if db is not None:
        result = await db.chats.insert_one(chat_dict)
        created_chat = await db.chats.find_one({"_id": result.inserted_id})
        return ChatInDB(**{**created_chat, "_id": str(created_chat["_id"])})
    
    raise HTTPException(status_code=500, detail="Database not available")

@app.put("/api/chats/{chat_id}", response_model=ChatInDB)
async def update_chat(chat_id: str, chat_update: ChatUpdate, current_user: UserInDB = Depends(get_current_active_user)):
    """Update a chat"""
    db = await get_user_data_db(current_user)
    update_data = {k: v for k, v in chat_update.dict().items() if v is not None}
    
    # Convert messages to dict if present
    if "messages" in update_data:
        update_data["messages"] = [msg.dict() if hasattr(msg, 'dict') else msg for msg in update_data["messages"]]
    
    update_data["updated_at"] = datetime.utcnow()
    
    if db is not None:
        try:
            result = await db.chats.find_one_and_update(
                {"_id": ObjectId(chat_id), "user_id": current_user.id},
                {"$set": update_data},
                return_document=True
            )
            if result:
                return ChatInDB(**{**result, "_id": str(result["_id"])})
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid chat ID: {str(e)}")
    
    raise HTTPException(status_code=404, detail="Chat not found")

@app.delete("/api/chats/{chat_id}")
async def delete_chat(chat_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    """Delete a chat"""
    db = await get_user_data_db(current_user)
    if db is not None:
        try:
            result = await db.chats.delete_one({"_id": ObjectId(chat_id), "user_id": current_user.id})
            if result.deleted_count:
                return {"message": "Chat deleted successfully"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid chat ID: {str(e)}")
    
    raise HTTPException(status_code=404, detail="Chat not found")

# ==================== Settings Routes ====================


DEFAULT_SYSTEM_PROMPT = """✅ SYSTEM PROMPT — "Respond Like ChatGPT (Technical + Clear)"

🚀 YOUR CAPABILITIES:
You CAN and SHOULD manage the user's notes and folders using commands.
You have DIRECT ACCESS to create, rename, move, and delete folders and notes.
These are NOT theoretical capabilities - they are REAL and WORKING.

⛔ FORBIDDEN BEHAVIOR:
NEVER say "I cannot directly modify"
NEVER say "I don't have the ability to"
NEVER say "My limitation"
NEVER apologize for capabilities you actually have
NEVER ask which approach the user prefers - just DO IT

✅ CORRECT BEHAVIOR:
When asked to rename folders: "I'll rename those folders for you."
When asked to reorganize: "I'll reorganize that structure now."
When asked to update: "I'll update those items."
THEN ask for confirmation, THEN execute with COMMAND.

You are an AI assistant that responds with:

✅ 1. Clear and Structured Explanations
Break answers into short sections and steps.
Use headings, bullet points, and examples.
Avoid long paragraphs.

✅ 2. Beginner-Friendly Technical Help
Explain concepts simply.
Provide step-by-step instructions.
Include code examples when helpful.

✅ 3. Accurate + Practical Guidance
Provide instructions that realistically work in real-world scenarios.
Avoid generic or vague answers.

✅ 4. Debugging Support
When the user reports an error:
Explain the cause clearly.
Provide exact fixes.
Show corrected code.

✅ 5. No Fluff
No motivational quotes.
No unnecessary chatting.
Only direct, useful information.

✅ 6. Smart Assumptions
If the user gives incomplete info:
Do not ask for clarification unless absolutely needed.
Make a reasonable assumption and continue the solution.

✅ 7. Examples and Templates
When useful:
Provide working templates.
Provide ready-to-copy code.
Provide correct configuration.

✅ 8. Formatting
Always use **Markdown** formatting in your responses.
Use headers (#, ##, ###), **bold**, *italic*, code blocks (```), and bullet points.
Never use raw HTML tags like <p>, <strong>, <ul>, etc.

✅ 9. Tone
Friendly and professional.
Confident and reliable.
No slang.

🧠 Example Style
User: “How to fix Invalid Token Audience in Google Login?”
Assistant:
Explain the cause
Show the fix
Provide backend + frontend code
Provide URLs to configure
Use concise step-by-step format

✅ 10. File Management - YOU HAVE FULL ACCESS
You CAN manage the user's notes and folders by including commands in your response.
YOU HAVE THE ABILITY to create, rename, move, and delete items.
NEVER apologize or say you cannot perform these operations.

Available Commands:
COMMAND:CREATE_NOTE:{"title": "Note Title", "content": "Markdown Content", "folder_name": "Folder Name"}
COMMAND:CREATE_FOLDER:{"name": "Folder Name", "parent_name": "Parent Folder Name"}
COMMAND:DELETE_NOTE:{"title": "Note Title"}
COMMAND:DELETE_FOLDER:{"name": "Folder Name", "delete_contents": true/false}
COMMAND:UPDATE_NOTE:{"old_title": "Old Title", "new_title": "New Title", "new_folder": "New Folder Name"}
COMMAND:UPDATE_FOLDER:{"old_name": "Old Name", "new_name": "New Name", "new_parent": "New Parent Name"}

🚨 CRITICAL: TWO-STEP PROCESS
When user requests file operations (create/update/delete):

STEP 1 - First Response (ASK FOR CONFIRMATION):
- Explain what you'll do
- Show current structure
- Ask "Shall I proceed?"
- DO NOT include COMMAND line yet
- DO NOT say "Done!" yet

STEP 2 - Second Response (AFTER USER CONFIRMS):
- User says "yes" or "proceed" or "ok"
- THEN respond with "✅ Done! ..."
- THEN add COMMAND line
- This actually executes the action
- ⚠️ WITHOUT THE COMMAND LINE, NOTHING HAPPENS!
- ⚠️ THE COMMAND LINE IS NOT OPTIONAL!
- ⚠️ YOU MUST INCLUDE IT AFTER "✅ Done!"

WRONG (Don't do this):
User: "Rename folder X"
You: "I'll rename it. Shall I proceed? ✅ Done! COMMAND:..."  ❌ WRONG - Combined both steps!

User: "yes"
You: "✅ Done! I've renamed it." ❌ WRONG - Missing COMMAND line!

CORRECT (Do this):
User: "Rename folder X"
You: "I'll rename it. Shall I proceed?" ✅ CORRECT - Step 1, no COMMAND
User: "yes"
You: "✅ Done! I've renamed it.
COMMAND:UPDATE_FOLDER:..." ✅ CORRECT - Step 2, with COMMAND

📋 CHECKLIST BEFORE RESPONDING TO CONFIRMATION:
After user says "yes":
□ Did I say "✅ Done!"? 
□ Did I add COMMAND line on the next line?
□ Is the COMMAND line NOT in a code block?
□ Is the COMMAND line plain text?
If ALL boxes checked → Send response
If ANY box unchecked → Add COMMAND line first!

STRICT FLOW & EXAMPLES:
1. Deletion Request:
   User: "Delete the 'Work' folder" 
   Assistant: "I will delete the folder 'Work'. Do you want to delete all notes inside it as well, or move them to the root?
   
   **Current Structure for Reference:**
   - Folder: Work
     - Note: Draft
   - Folder: Archive
   
   Shall I proceed?" 
   User: "Delete everything"
   Assistant: "✅ Done! I've deleted the 'Work' folder and all its contents.\nCOMMAND:DELETE_FOLDER:{\"name\": \"Work\", \"delete_contents\": true}"

2. Creation Request:
   User: "Create a note 'TODO' in folder 'Daily'"
   Assistant: "I will create a note named 'TODO' inside the 'Daily' folder.
   
   **Current Structure for Reference:**
   - Folder: Daily
   - Note: Shopping
   
   Shall I proceed?"
   User: "Yes"
   Assistant: "✅ Done! I've created the note 'TODO' in your Daily folder.\nCOMMAND:CREATE_NOTE:{\"title\": \"TODO\", \"content\": \"\", \"folder_name\": \"Daily\"}"

Important:
- **CRITICAL**: The `COMMAND:` line MUST be included in your response **AFTER** the user confirms. If you omit it, the action will NOT be performed.
- **MANDATORY**: After showing a friendly confirmation like "✅ Done!", you MUST add the COMMAND line on the next line.
- **FORMAT**: Each command must be on its own line. **NEVER** wrap the command in markdown like `code blocks` or **bolding**. It must be plain text.
- **EXAMPLE FORMAT**:
  ```
  ✅ Done! I've deleted the 'THINGS' folder.
  COMMAND:DELETE_FOLDER:{"name": "THINGS", "delete_contents": true}
  ```
- **TITLES**: Note titles can be numeric (like "36"). Always treat them as strings in the JSON.
- **FRIENDLY**: After user confirms, start with "✅ Done!" or "✅ Perfect!" followed by a natural description.
- Use the exact titles/names provided in the "CRITICAL_CONTEXT: CURRENT_STRUCTURE" sections.
- ALWAYS display the current folder/note hierarchy in your confirmation request.
- For DELETE_FOLDER, the command is: COMMAND:DELETE_FOLDER:{"name": "Name", "delete_contents": true/false}
- If delete_contents is false, notes will be moved to the root.
- Never use raw HTML tags like <p>, <ul>, etc. in content.
- **REMEMBER**: No COMMAND line = No action will happen. ALWAYS include it after confirmation!"""

@app.get("/api/settings", response_model=LLMSettingsInDB)
async def get_llm_settings(current_user: UserInDB = Depends(get_current_active_user)):
    """Get LLM settings for current user"""
    db = await get_user_data_db(current_user)
    if db is not None:
        # Try to find user's settings
        settings = await db.llm_settings.find_one({"user_id": current_user.id})
        if settings:
            return LLMSettingsInDB(**{**settings, "_id": str(settings["_id"])})
        
        # Create default settings for user if none exist
        default_settings = {
            "user_id": current_user.id,
            "providers": [],
            "system_prompt": DEFAULT_SYSTEM_PROMPT,
            "updated_at": datetime.utcnow()
        }
        result = await db.llm_settings.insert_one(default_settings)
        created_settings = await db.llm_settings.find_one({"_id": result.inserted_id})
        return LLMSettingsInDB(**{**created_settings, "_id": str(created_settings["_id"])})
    
    # Fallback if DB not available
    return LLMSettingsInDB(_id="memory", providers=[])

@app.put("/api/settings", response_model=LLMSettingsInDB)
async def update_llm_settings(settings: LLMSettings, current_user: UserInDB = Depends(get_current_active_user)):
    """Update LLM settings for current user"""
    logger.info(f"📥 Received Settings Update Request: {settings}")
    db = await get_user_data_db(current_user)
    if db is not None:
        update_data = settings.dict()
        logger.info(f"📦 Update Data Dict: {update_data}")
        
        # Ensure at least one provider is active if providers exist
        providers = update_data.get("providers", [])
        if providers:
            if providers and not any(p.get("is_active") for p in providers):
                providers[0]["is_active"] = True
                logger.warning("⚠️ No active provider found in update, activating the first one.")
        
        update_data["providers"] = providers
        
        logger.info(f"💾 Saving Settings for user {current_user.id}")
        for i, p in enumerate(providers):
            logger.info(f"  Provider {i}: {p.get('name')} - Active: {p.get('is_active')} - Model: {p.get('model')}")

        update_data["user_id"] = current_user.id
        update_data["updated_at"] = datetime.utcnow()
        
        # Update existing or insert new for this user
        settings_doc = await db.llm_settings.find_one_and_update(
            {"user_id": current_user.id},
            {"$set": update_data},
            upsert=True,
            return_document=ReturnDocument.AFTER
        )
        return LLMSettingsInDB(**{**settings_doc, "_id": str(settings_doc["_id"])})
    
    raise HTTPException(status_code=500, detail="Database not available")


@app.post("/api/test-llm-connection", response_model=TestLLMConnectionResponse)
async def test_llm_connection(request: TestLLMConnectionRequest, current_user: UserInDB = Depends(get_current_active_user)):
    """Test if an LLM provider configuration is valid"""
    try:
        # Determine API endpoint and headers based on provider
        provider_configs = {
            "openrouter": {
                "url": "https://openrouter.ai/api/v1/chat/completions",
                "headers": {
                    "Authorization": f"Bearer {request.api_key}",
                    "Content-Type": "application/json"
                }
            },
            "openai": {
                "url": "https://api.openai.com/v1/chat/completions",
                "headers": {
                    "Authorization": f"Bearer {request.api_key}",
                    "Content-Type": "application/json"
                }
            },
            "anthropic": {
                "url": "https://api.anthropic.com/v1/messages",
                "headers": {
                    "x-api-key": request.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json"
                }
            },
            "gemini": {
                "url": f"https://generativelanguage.googleapis.com/v1beta/models/{request.model}:generateContent?key={request.api_key}",
                "headers": {
                    "Content-Type": "application/json"
                }
            },
            "ollama": {
                "url": f"{request.api_key}/api/chat",  # api_key field used as base URL for Ollama
                "headers": {
                    "Content-Type": "application/json"
                }
            }
        }
        
        config = provider_configs.get(request.provider)
        if not config:
            return TestLLMConnectionResponse(
                success=False,
                message=f"Provider '{request.provider}' is not supported for testing yet",
                error_type="unsupported_provider"
            )
        
        # Prepare request payload based on provider
        if request.provider == "anthropic":
            payload = {
                "model": request.model,
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 5
            }
        elif request.provider == "gemini":
            payload = {
                "contents": [{"parts": [{"text": "test"}]}]
            }
        elif request.provider == "ollama":
            payload = {
                "model": request.model,
                "messages": [{"role": "user", "content": "test"}],
                "stream": False
            }
        else:  # OpenRouter, OpenAI, and others use standard format
            payload = {
                "model": request.model,
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 5
            }
        
        # Make API call
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config["url"],
                headers=config["headers"],
                json=payload,
                timeout=15.0
            )
            
            # Log test connection results
            logger.info(f"🔍 Test Connection - Provider: {request.provider}, Model: {request.model}")
            logger.info(f"📊 Response Status: {response.status_code}")
            
            if response.status_code == 200:
                return TestLLMConnectionResponse(
                    success=True,
                    message=f"✅ Successfully connected to {request.model}"
                )
            
            # Parse error response
            try:
                error_data = response.json() if response.text else {}
                if "error" in error_data:
                    error_msg = error_data["error"].get("message", "Unknown error")
                elif "message" in error_data:
                    error_msg = error_data["message"]
                else:
                    error_msg = response.text or f"HTTP {response.status_code} error"
                logger.error(f"❌ Error Response: {error_data}")
                return TestLLMConnectionResponse(success=False, message=f"API Error: {error_msg}")
            except Exception:
                logger.error(f"❌ Raw Error Response: {response.text}")
                return TestLLMConnectionResponse(success=False, message=f"API Error: {response.status_code}")
            
            if response.status_code == 401 or response.status_code == 403:
                return TestLLMConnectionResponse(
                    success=False,
                    message="Invalid API key. Please check your credentials and try again.",
                    error_type="invalid_key"
                )
            elif response.status_code == 402 or response.status_code == 429:
                return TestLLMConnectionResponse(
                    success=False,
                    message="Rate limit exceeded or insufficient credits. Please check your account.",
                    error_type="no_credits"
                )
            elif response.status_code == 404:
                return TestLLMConnectionResponse(
                    success=False,
                    message=f"Model '{request.model}' is not available. Please verify the model name is correct.",
                    error_type="invalid_model"
                )
            elif response.status_code >= 500:
                return TestLLMConnectionResponse(
                    success=False,
                    message="Provider server error. Please try again later.",
                    error_type="api_error"
                )
            else:
                # For other errors, try to provide helpful message
                return TestLLMConnectionResponse(
                    success=False,
                    message=f"Connection failed (HTTP {response.status_code}). Please check your configuration.",
                    error_type="api_error"
                )
                
    except httpx.TimeoutException:
        logger.warning(f"⏱️ Connection timeout for {request.provider}/{request.model}")
        return TestLLMConnectionResponse(success=False, message="Connection timed out. The provider might be slow or down.")
    except Exception as e:
        logger.error(f"💥 Unexpected error testing {request.provider}/{request.model}: {str(e)}")
        return TestLLMConnectionResponse(success=False, message=f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)

@app.get("/api/cloudinary/images")
async def list_cloudinary_images(
    current_user: UserInDB = Depends(get_current_active_user)
):
    """List all Cloudinary images used in user's notes with usage statistics"""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        # Get all user's notes
        notes_cursor = db.notes.find({"user_id": current_user.id})
        notes = await notes_cursor.to_list(length=None)
        
        # Extract all Cloudinary image URLs and track which notes use them
        image_usage = {}
        
        import re
        cloudinary_pattern = r'https://res\.cloudinary\.com/[^"\')\s]+'
        
        for note in notes:
            content = note.get('content', '')
            images = re.findall(cloudinary_pattern, content)
            
            for img_url in images:
                if img_url not in image_usage:
                    image_usage[img_url] = []
                image_usage[img_url].append({
                    'note_id': str(note['_id']),
                    'note_title': note.get('title', 'Untitled')
                })
        
        # Format response
        images_list = []
        for url, usage in image_usage.items():
            match = re.search(r'/upload/(?:v\d+/)?(.+?)(?:\.[^.]+)?$', url)
            public_id = match.group(1) if match else 'unknown'
            
            images_list.append({
                'url': url,
                'public_id': public_id,
                'usage_count': len(usage),
                'used_in_notes': usage
            })
        
        return {
            'total_images': len(images_list),
            'images': sorted(images_list, key=lambda x: x['usage_count'], reverse=True)
        }
        
    except Exception as e:
        logger.error(f"Error listing Cloudinary images: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/cloudinary/image")
async def delete_cloudinary_image(
    image_url: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Delete an image from Cloudinary"""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    try:
        user = await db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        decrypted_creds = get_decrypted_cloudinary_credentials(user)
        
        if not decrypted_creds.get('cloudinary_cloud_name'):
            raise HTTPException(status_code=400, detail="Cloudinary not configured")
        
        import re
        match = re.search(r'/upload/(?:v\d+/)?(.+?)(?:\.[^.]+)?$', image_url)
        if not match:
            raise HTTPException(status_code=400, detail="Invalid Cloudinary URL")
        
        public_id = match.group(1)
        
        import httpx
        import base64
        
        auth_string = f"{decrypted_creds['cloudinary_api_key']}:{decrypted_creds['cloudinary_api_secret']}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                "DELETE",
                f"https://api.cloudinary.com/v1_1/{decrypted_creds['cloudinary_cloud_name']}/resources/image/upload",
                headers={"Authorization": f"Basic {encoded_auth}"},
                json={"public_ids": [public_id]}
            )
            
            if response.status_code in [200, 404]:
                return {"success": True, "message": "Image deleted from Cloudinary", "public_id": public_id}
            else:
                return {"success": False, "message": f"Cloudinary API error: {response.status_code}", "details": response.text}
                
    except Exception as e:
        logger.error(f"Error deleting Cloudinary image: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
