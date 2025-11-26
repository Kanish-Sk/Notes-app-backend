from fastapi import FastAPI, HTTPException, status, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime, timedelta
from bson import ObjectId
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv
import httpx

from database import connect_to_mongo, close_mongo_connection, get_database
from models import (
    NoteCreate, NoteUpdate, NoteInDB, 
    FolderCreate, FolderUpdate, FolderInDB,
    AIRequest, AIResponse, 
    ChatCreate, ChatUpdate, ChatInDB, 
    LLMProvider, LLMSettings, LLMSettingsInDB,
    User, UserInDB, UserCreate, UserLogin, Token, RefreshTokenData, GoogleAuthRequest,
    ForgotPasswordRequest, VerifyResetCodeRequest, ResetPasswordRequest, ShareNoteRequest,
    MongoDBConnectionRequest, MongoDBConnectionResponse
)
from auth import (
    get_password_hash, 
    authenticate_user, 
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
    get_current_user,
    get_current_active_user,
    get_user_by_email,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS
)
from email_utils import send_share_email

load_dotenv()

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

@app.get("/api/stats")
async def get_statistics():
    """Get app statistics - no auth required"""
    db = get_database()
    if db is None:
        return {"users": 0, "notes": 0}
    
    try:
        # Count total users
        users_count = await db.users.count_documents({})
        
        # Count total notes
        notes_count = await db.notes.count_documents({})
        
        return {
            "users": users_count,
            "notes": notes_count
        }
    except Exception as e:
        print(f"Error getting statistics: {e}")
        return {"users": 0, "notes": 0}

# ==================== Authentication Routes ====================

@app.post("/api/auth/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """Register a new user with email and password"""
    from user_database import verify_mongodb_connection, encrypt_connection_string
    
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
    if db is not None:
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
            "picture": user.picture
        }
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
            # In production, you should properly verify the JWT signature
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
                "created_at": datetime.utcnow()
            }
            
            result = await db.users.insert_one(user_dict)
            created_user = await db.users.find_one({"_id": result.inserted_id})
            user = UserInDB(**{**created_user, "_id": str(created_user["_id"])})
        
        # Create JWT access token
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
                "picture": user.picture
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Google auth error: {str(e)}")
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
    
    # Search by email or full_name (case-insensitive)
    search_regex = {"$regex": query, "$options": "i"}
    users = await db.users.find({
        "$or": [
            {"email": search_regex},
            {"full_name": search_regex}
        ],
        "is_active": True
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
    from user_database import verify_mongodb_connection
    
    success, message = await verify_mongodb_connection(request.connection_string)
    return MongoDBConnectionResponse(success=success, message=message)

@app.post("/api/user/update-database")
async def update_user_database(
    request: MongoDBConnectionRequest,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Update user's MongoDB connection string (for Google login users)"""
    from user_database import verify_mongodb_connection, encrypt_connection_string
    
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
    
    return {"message": "Database connection updated successfully", "has_database": True}

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
    """Get all notes (owned and shared)"""
    db = get_database()
    if db is not None:
        # Get owned notes and notes shared with user
        notes = await db.notes.find({
            "$or": [
                {"user_id": current_user.id},
                {"shared_with": {"$in": [current_user.email.lower()]}}
            ]
        }).sort("updated_at", -1).to_list(100)
        return [NoteInDB(**{**note, "_id": str(note["_id"])}) for note in notes]
    else:
        # Fallback to in-memory storage
        return list(notes_storage.values())

@app.get("/api/notes/{note_id}", response_model=NoteInDB)
async def get_note(note_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    """Get a specific note by ID (if owned or shared)"""
    db = get_database()
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
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
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
    
    # Check for duplicate folder name in the same parent folder
    existing_duplicate = await db.folders.find_one({
        "user_id": current_user.id,
        "parent_id": folder.parent_id,
        "name": folder.name
    })
    
    if existing_duplicate:
        raise HTTPException(status_code=400, detail="A folder with this name already exists in this location")
    
    new_folder = await db.folders.insert_one(folder_dict)
    created_folder = await db.folders.find_one({"_id": new_folder.inserted_id})
    return FolderInDB(**{**created_folder, "_id": str(created_folder["_id"])})

@app.get("/api/folders", response_model=List[FolderInDB])
async def list_folders(current_user: UserInDB = Depends(get_current_active_user)):
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Get owned folders and folders shared with user
    folders = await db.folders.find({
        "$or": [
            {"user_id": current_user.id},
            {"shared_with": {"$in": [current_user.email.lower()]}}
        ]
    }).to_list(1000)
    return [FolderInDB(**{**folder, "_id": str(folder["_id"])}) for folder in folders]

@app.put("/api/folders/{folder_id}", response_model=FolderInDB)
async def update_folder(folder_id: str, folder: FolderUpdate, current_user: UserInDB = Depends(get_current_active_user)):
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
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
    move_to_root: bool = True, 
    destination_folder_id: Optional[str] = None,
    current_user: UserInDB = Depends(get_current_active_user)
):
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Check ownership
    existing_folder = await db.folders.find_one({"_id": ObjectId(folder_id)})
    if not existing_folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    
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
    """Share a folder with another user by email"""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Check ownership
    existing_folder = await db.folders.find_one({"_id": ObjectId(folder_id), "user_id": current_user.id})
    if not existing_folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    
    # Normalize email
    recipient_email = share_request.email.strip().lower()
    
    # Check if already shared with this user
    shared_with = existing_folder.get("shared_with", [])
    if recipient_email in shared_with:
        raise HTTPException(status_code=400, detail="Folder already shared with this user")
    
    # Check if recipient exists
    recipient = await get_user_by_email(recipient_email)
    is_new_user = recipient is None
    
    # Update folder's shared_with list
    await db.folders.update_one(
        {"_id": ObjectId(folder_id)},
        {"$addToSet": {"shared_with": recipient_email}}
    )
    
    # Send email notification in background
    background_tasks.add_task(
        send_share_email,
        to_email=recipient_email,
        sender_name=current_user.full_name or current_user.email,
        note_title=f"Folder: {existing_folder.get('name', 'Untitled')}",
        is_new_user=is_new_user
    )
    
    return {
        "message": f"Folder shared with {recipient_email}",
        "is_new_user": is_new_user
    }


# ==================== Notes Routes ====================

@app.post("/api/notes", response_model=NoteInDB, status_code=status.HTTP_201_CREATED)
async def create_note(note: NoteCreate, current_user: UserInDB = Depends(get_current_active_user)):
    """Create a new note"""
    db = get_database()
    
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
        "shared_with": [],  # Initialize empty
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    if db is not None:
        result = await db.notes.insert_one(note_dict)
        created_note = await db.notes.find_one({"_id": result.inserted_id})
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
    db = get_database()
    
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
async def delete_note(note_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    """Delete a note (only owner can delete)"""
    db = get_database()
    if db is not None:
        try:
            # First check if note exists and user has delete permission
            note = await db.notes.find_one({"_id": ObjectId(note_id)})
            if not note:
                raise HTTPException(status_code=404, detail="Note not found")
            
            # Check if user can edit (only owner)
            if not can_edit_note(note, current_user.id):
                raise HTTPException(status_code=403, detail="You don't have permission to delete this note. Only the owner can delete.")
            
            result = await db.notes.delete_one({"_id": ObjectId(note_id)})
            if result.deleted_count:
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
    """Share a note with another user by email"""
    db = get_database()
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    
    # Get the note
    try:
        note = await db.notes.find_one({"_id": ObjectId(note_id)})
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid note ID: {str(e)}")
    
    # Normalize email
    recipient_email = share_request.email.strip().lower()
    
    # Check if already shared with this user
    shared_with = note.get("shared_with", [])
    if recipient_email in shared_with:
        raise HTTPException(status_code=400, detail="Note already shared with this user")
    
    # Check if recipient exists
    recipient = await get_user_by_email(recipient_email)
    is_new_user = recipient is None
    
    # Update note's shared_with list
    await db.notes.update_one(
        {"_id": ObjectId(note_id)},
        {"$addToSet": {"shared_with": recipient_email}}
    )
    
    # Send email notification in background
    background_tasks.add_task(
        send_share_email,
        to_email=recipient_email,
        sender_name=current_user.full_name or current_user.email,
        note_title=note.get("title", "Untitled"),
        is_new_user=is_new_user
    )
    
    return {
        "message": f"Note shared with {recipient_email}",
        "is_new_user": is_new_user
    }

# ==================== AI Assistant Routes ====================

@app.post("/api/ai/chat", response_model=AIResponse)
async def ai_chat(request: AIRequest, current_user: UserInDB = Depends(get_current_active_user)):
    """AI assistant endpoint using user-configured LLM provider from Settings"""
    import os
    
    db = get_database()
    if db is None:
        return AIResponse(
            message="Database not available. Please try again later.",
            updated_content=None
        )
    
    # Get user's LLM settings from database
    settings_doc = await db.llm_settings.find_one({"user_id": current_user.id})
    
    if not settings_doc or not settings_doc.get("providers"):
        return AIResponse(
            message="AI assistant is not configured. Please add an LLM provider in Settings (⚙️ icon).",
            updated_content=None
        )
    
    # Get active providers
    providers = settings_doc.get("providers", [])
    active_providers = [p for p in providers if p.get("is_active", False)]
    
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
    model = selected_provider.get("model", "openai/gpt-4o-mini")
    
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
        provider_system_prompt = selected_provider.get("system_prompt", "").strip()
        global_system_prompt = settings_doc.get("system_prompt", "").strip()
        
        if use_global and global_system_prompt:
            # Provider explicitly wants to use global prompt
            system_prompt = global_system_prompt
        elif provider_system_prompt:
            # Use provider-specific system prompt
            system_prompt = provider_system_prompt
        elif global_system_prompt:
            # Fall back to globalprompt
            system_prompt = global_system_prompt
        else:
            # Use default system prompt based on edit mode
            if request.edit_mode:
                system_prompt = """You are a helpful AI assistant for a note-taking app. 
Your task is to help users improve their notes. You can:
- Summarize content
- Improve writing clarity and structure
- Fix grammar and spelling
- Add formatting suggestions
- Reorganize information

When editing, provide the complete updated note content in markdown format.
Be concise and helpful."""
            else:
                system_prompt = """You are a helpful AI assistant for a note-taking app.
Provide concise, helpful responses to user questions about their notes.
Use markdown formatting when appropriate.
Be friendly and constructive."""
        
        # Prepare messages
        messages = [
            {"role": "system", "content": system_prompt},
        ]
        
        # Add context about the current note if there is content
        if request.current_content:
            messages.append({
                "role": "system",
                "content": f"Current note content:\n\n{request.current_content}"
            })
        
        # Add user message
        messages.append({
            "role": "user",
            "content": request.message
        })
        
        # Make direct API call to OpenRouter using httpx
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,  # Use model from user settings
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 2000
                },
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"OpenRouter API error: {response.status_code} - {response.text}")
            
            result = response.json()
            ai_message = result["choices"][0]["message"]["content"]
        
        # If edit mode is enabled, prepare updated content
        updated_content = None
        if request.edit_mode:
            # Check if the AI provided a complete note or just suggestions
            if ai_message.startswith('#') or len(ai_message) > len(request.current_content) * 0.5:
                # AI provided complete content
                updated_content = ai_message
            else:
                # AI provided suggestions, append them
                updated_content = request.current_content + f"\n\n---\n\n**AI Suggestions:**\n{ai_message}"
        
        return AIResponse(message=ai_message, updated_content=updated_content)
    
    except Exception as e:
        print(f"AI Chat Error: {str(e)}")
        # Return a friendly error message
        return AIResponse(
            message=f"Sorry, I encountered an error: {str(e)}. Please try again.",
            updated_content=None
        )

# ==================== Chat History Routes ====================

@app.get("/api/chats", response_model=List[ChatInDB])
async def get_all_chats():
    """Get all chat histories"""
    db = get_database()
    if db is not None:
        chats = await db.chats.find().sort("updated_at", -1).to_list(100)
        return [ChatInDB(**{**chat, "_id": str(chat["_id"])}) for chat in chats]
    return []

@app.get("/api/chats/{chat_id}", response_model=ChatInDB)
async def get_chat(chat_id: str):
    """Get a specific chat by ID"""
    db = get_database()
    if db is not None:
        try:
            chat = await db.chats.find_one({"_id": ObjectId(chat_id)})
            if chat:
                return ChatInDB(**{**chat, "_id": str(chat["_id"])})
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid chat ID: {str(e)}")
    raise HTTPException(status_code=404, detail="Chat not found")

@app.post("/api/chats", response_model=ChatInDB, status_code=status.HTTP_201_CREATED)
async def create_chat(chat: ChatCreate):
    """Create a new chat"""
    db = get_database()
    chat_dict = {
        "title": chat.title,
        "messages": [msg.dict() for msg in chat.messages],
        "note_id": chat.note_id,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    if db is not None:
        result = await db.chats.insert_one(chat_dict)
        created_chat = await db.chats.find_one({"_id": result.inserted_id})
        return ChatInDB(**{**created_chat, "_id": str(created_chat["_id"])})
    
    raise HTTPException(status_code=500, detail="Database not available")

@app.put("/api/chats/{chat_id}", response_model=ChatInDB)
async def update_chat(chat_id: str, chat_update: ChatUpdate):
    """Update a chat"""
    db = get_database()
    update_data = {k: v for k, v in chat_update.dict().items() if v is not None}
    
    # Convert messages to dict if present
    if "messages" in update_data:
        update_data["messages"] = [msg.dict() if hasattr(msg, 'dict') else msg for msg in update_data["messages"]]
    
    update_data["updated_at"] = datetime.utcnow()
    
    if db is not None:
        try:
            result = await db.chats.find_one_and_update(
                {"_id": ObjectId(chat_id)},
                {"$set": update_data},
                return_document=True
            )
            if result:
                return ChatInDB(**{**result, "_id": str(result["_id"])})
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid chat ID: {str(e)}")
    
    raise HTTPException(status_code=404, detail="Chat not found")

@app.delete("/api/chats/{chat_id}")
async def delete_chat(chat_id: str):
    """Delete a chat"""
    db = get_database()
    if db is not None:
        try:
            result = await db.chats.delete_one({"_id": ObjectId(chat_id)})
            if result.deleted_count:
                return {"message": "Chat deleted successfully"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid chat ID: {str(e)}")
    
    raise HTTPException(status_code=404, detail="Chat not found")

# ==================== Settings Routes ====================

@app.get("/api/settings", response_model=LLMSettingsInDB)
async def get_settings(current_user: UserInDB = Depends(get_current_active_user)):
    """Get user's LLM settings"""
    db = get_database()
    if db is not None:
        # Try to find user's settings
        settings = await db.llm_settings.find_one({"user_id": current_user.id})
        if settings:
            return LLMSettingsInDB(**{**settings, "_id": str(settings["_id"])})
        
        # Create default settings for user if none exist
        default_settings = {
            "user_id": current_user.id,
            "providers": [],
            "updated_at": datetime.utcnow()
        }
        result = await db.llm_settings.insert_one(default_settings)
        created_settings = await db.llm_settings.find_one({"_id": result.inserted_id})
        return LLMSettingsInDB(**{**created_settings, "_id": str(created_settings["_id"])})
    
    # Fallback if DB not available
    return LLMSettingsInDB(_id="memory", providers=[])

@app.put("/api/settings", response_model=LLMSettingsInDB)
async def update_settings(settings: LLMSettings, current_user: UserInDB = Depends(get_current_active_user)):
    """Update user's LLM settings"""
    db = get_database()
    if db is not None:
        update_data = settings.dict()
        update_data["user_id"] = current_user.id
        update_data["updated_at"] = datetime.utcnow()
        
        # Update existing or insert new for this user
        settings_doc = await db.llm_settings.find_one_and_update(
            {"user_id": current_user.id},
            {"$set": update_data},
            upsert=True,
            return_document=True
        )
        return LLMSettingsInDB(**{**settings_doc, "_id": str(settings_doc["_id"])})
    
    raise HTTPException(status_code=500, detail="Database not available")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
