from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional, List
import os
import json
import re
import base64
from dotenv import load_dotenv
import httpx

from app.models import (
    NoteCreate, NoteUpdate, NoteInDB,
    UserCreate, UserInDB, UserLogin,
    FolderCreate, FolderUpdate, FolderInDB,
    ShareNoteRequest, LLMSettings,
    Token, RefreshTokenData, GoogleAuthRequest,
    ForgotPasswordRequest, VerifyResetCodeRequest, ResetPasswordRequest,
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
from app.database import connect_to_db, close_db, get_pool
from app.crypto import encrypt_value, decrypt_value
from app.email_utils import send_password_reset_email, send_share_notification_email
from app.logger import setup_logging, get_logger

load_dotenv()

setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_db()
    yield
    await close_db()


app = FastAPI(title="MindFlow AI API", version="2.0.0", lifespan=lifespan)

frontend_url = os.getenv("FRONTEND_URL", "")
allowed_origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:3000",
]
if frontend_url:
    allowed_origins.append(frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _note_from_row(row, shared_with=None, is_shared=False, shared_by=None,
                   original_owner_id=None, original_owner_email=None) -> NoteInDB:
    d = dict(row)
    shared_list = list(shared_with) if shared_with else list(d.pop("shared_with", []) or [])
    # pop the joined shared_with col if present
    d.pop("shared_with", None)
    d.pop("shared_by_email", None)
    return NoteInDB(
        **{
            "_id": str(d.pop("id")),
            "user_id": str(d["user_id"]) if d.get("user_id") else None,
            "folder_id": str(d["folder_id"]) if d.get("folder_id") else None,
            "title": d.get("title", "Untitled"),
            "content": d.get("content", ""),
            "shared_with": shared_list,
            "created_at": d.get("created_at"),
            "updated_at": d.get("updated_at"),
            "is_shared": is_shared,
            "shared_by": shared_by,
            "original_owner_id": original_owner_id,
            "original_owner_email": original_owner_email,
        }
    )


def _folder_from_row(row, shared_with=None, is_shared=False, shared_by=None,
                     original_owner_id=None) -> FolderInDB:
    d = dict(row)
    shared_list = list(shared_with) if shared_with else list(d.pop("shared_with", []) or [])
    d.pop("shared_with", None)
    d.pop("shared_by_email", None)
    return FolderInDB(
        **{
            "_id": str(d.pop("id")),
            "user_id": str(d["user_id"]) if d.get("user_id") else "",
            "parent_id": str(d["parent_id"]) if d.get("parent_id") else None,
            "name": d.get("name", "Untitled"),
            "shared_with": shared_list,
            "created_at": d.get("created_at"),
            "is_shared": is_shared,
            "shared_by": shared_by,
            "original_owner_id": original_owner_id,
        }
    )


def _chat_from_row(row) -> ChatInDB:
    d = dict(row)
    messages_raw = d.get("messages") or []
    if isinstance(messages_raw, str):
        messages_raw = json.loads(messages_raw)
    from app.models import ChatMessage
    messages = []
    for m in messages_raw:
        if isinstance(m, dict):
            messages.append(ChatMessage(**m))
    return ChatInDB(
        **{
            "_id": str(d["id"]),
            "user_id": str(d["user_id"]) if d.get("user_id") else None,
            "note_id": str(d["note_id"]) if d.get("note_id") else None,
            "title": d.get("title", "New Chat"),
            "messages": messages,
            "created_at": d.get("created_at"),
            "updated_at": d.get("updated_at"),
        }
    )


async def _get_note_shared_with(pool, note_id: str) -> List[str]:
    rows = await pool.fetch(
        "SELECT shared_with_email FROM note_shares WHERE note_id = $1::uuid", note_id
    )
    return [r["shared_with_email"] for r in rows]


async def _get_folder_shared_with(pool, folder_id: str) -> List[str]:
    rows = await pool.fetch(
        "SELECT shared_with_email FROM folder_shares WHERE folder_id = $1::uuid", folder_id
    )
    return [r["shared_with_email"] for r in rows]


def get_decrypted_cloudinary_credentials(user_row: dict) -> dict:
    result = {
        "cloudinary_cloud_name": user_row.get("cloudinary_cloud_name"),
        "cloudinary_api_key": None,
        "cloudinary_api_secret": None,
    }
    for field in ("cloudinary_api_key", "cloudinary_api_secret"):
        raw = user_row.get(field)
        if raw:
            try:
                result[field] = decrypt_value(raw)
            except Exception as e:
                logger.warning(f"Failed to decrypt {field}: {e}")
    return result


async def cleanup_note_images(note_content: str, user_id: str):
    pool = get_pool()
    if not pool:
        return
    user_row = await pool.fetchrow("SELECT * FROM users WHERE id = $1::uuid", user_id)
    if not user_row:
        return
    creds = get_decrypted_cloudinary_credentials(dict(user_row))
    if not all([creds.get("cloudinary_cloud_name"), creds.get("cloudinary_api_key"), creds.get("cloudinary_api_secret")]):
        return

    cloudinary_pattern = r'https://res\.cloudinary\.com/[^\"\'\)\s]+'
    urls = re.findall(cloudinary_pattern, note_content)
    if not urls:
        return

    public_ids = list({
        m.group(1)
        for url in urls
        for m in [re.search(r'/upload/(?:v\d+/)?(.+?)(?:\.[^.]+)?$', url)]
        if m
    })
    if not public_ids:
        return

    try:
        auth_string = f"{creds['cloudinary_api_key']}:{creds['cloudinary_api_secret']}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                "DELETE",
                f"https://api.cloudinary.com/v1_1/{creds['cloudinary_cloud_name']}/resources/image/upload",
                headers={"Authorization": f"Basic {encoded_auth}"},
                json={"public_ids": public_ids},
            )
            if response.status_code == 200:
                logger.info(f"🗑️ Cleaned up {len(public_ids)} Cloudinary images")
            else:
                logger.warning(f"⚠️ Cloudinary cleanup: {response.status_code}")
    except Exception as e:
        logger.error(f"Error cleaning up Cloudinary images: {e}")


# ── Root ──────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"message": "MindFlow AI API", "version": "2.0.0"}


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_statistics():
    pool = get_pool()
    try:
        users_count = await pool.fetchval("SELECT COUNT(*) FROM users")
        notes_count = await pool.fetchval("SELECT COUNT(*) FROM notes")
        return {"users": users_count, "notes": notes_count}
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return {"users": 0, "notes": 0}


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/api/auth/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    pool = get_pool()

    existing = await get_user_by_email(user_data.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user_data.password)

    row = await pool.fetchrow(
        """
        INSERT INTO users (email, full_name, hashed_password, provider, refresh_tokens, is_active, created_at)
        VALUES ($1, $2, $3, 'email', '{}', true, NOW())
        RETURNING *
        """,
        user_data.email,
        user_data.full_name,
        hashed_password,
    )
    user = _user_from_row(row)

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(
        data={"sub": user.email},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    await pool.execute(
        "UPDATE users SET refresh_tokens = array_append(refresh_tokens, $1) WHERE id = $2::uuid",
        refresh_token, user.id,
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        user={"id": user.id, "email": user.email, "full_name": user.full_name, "picture": user.picture},
    )


def _user_from_row(row) -> UserInDB:
    d = dict(row)
    d["_id"] = str(d.pop("id"))
    d.setdefault("refresh_tokens", [])
    return UserInDB(**d)


@app.post("/api/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    pool = get_pool()
    user = await authenticate_user(user_data.email, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(
        data={"sub": user.email},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    await pool.execute(
        "UPDATE users SET refresh_tokens = array_append(refresh_tokens, $1) WHERE id = $2::uuid",
        refresh_token, user.id,
    )

    # Fetch full row for Cloudinary creds
    user_row = await pool.fetchrow("SELECT * FROM users WHERE id = $1::uuid", user.id)
    creds = get_decrypted_cloudinary_credentials(dict(user_row))

    user_response = {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "picture": user.picture,
        **creds,
    }

    return Token(access_token=access_token, refresh_token=refresh_token, user=user_response)


@app.post("/api/auth/google", response_model=Token)
async def google_auth(auth_data: GoogleAuthRequest):
    google_client_id = os.getenv("GOOGLE_CLIENT_ID")
    pool = get_pool()

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={auth_data.credential}"
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="Invalid Google credential")
            google_user = resp.json()
            if google_user.get("aud") != google_client_id:
                raise HTTPException(status_code=400, detail="Invalid token audience")

        user = await get_user_by_email(google_user["email"])

        if not user:
            row = await pool.fetchrow(
                """
                INSERT INTO users (email, full_name, picture, provider, refresh_tokens, is_active, created_at)
                VALUES ($1, $2, $3, 'google', '{}', true, NOW())
                RETURNING *
                """,
                google_user["email"],
                google_user.get("name"),
                google_user.get("picture"),
            )
            user = _user_from_row(row)

        access_token = create_access_token(
            data={"sub": user.email},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )
        refresh_token = create_refresh_token(
            data={"sub": user.email},
            expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        )

        await pool.execute(
            "UPDATE users SET refresh_tokens = array_append(refresh_tokens, $1) WHERE id = $2::uuid",
            refresh_token, user.id,
        )

        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            user={"id": user.id, "email": user.email, "full_name": user.full_name, "picture": user.picture},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google auth error: {e}")
        raise HTTPException(status_code=400, detail=f"Google authentication failed: {str(e)}")


@app.post("/api/auth/refresh", response_model=Token)
async def refresh_access_token(token_data: RefreshTokenData):
    email = await verify_refresh_token(token_data.refresh_token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(
        access_token=access_token,
        refresh_token=token_data.refresh_token,
        user={"id": user.id, "email": user.email, "full_name": user.full_name, "picture": user.picture},
    )


@app.post("/api/auth/logout")
async def logout(token_data: RefreshTokenData, current_user: UserInDB = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    pool = get_pool()
    await pool.execute(
        "UPDATE users SET refresh_tokens = array_remove(refresh_tokens, $1) WHERE id = $2::uuid",
        token_data.refresh_token, current_user.id,
    )
    return {"message": "Successfully logged out"}


@app.get("/api/auth/me", response_model=dict)
async def get_current_user_info(current_user: UserInDB = Depends(get_current_active_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "picture": current_user.picture,
        "provider": current_user.provider,
    }


@app.post("/api/auth/forgot-password")
async def forgot_password(request_data: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    import random
    pool = get_pool()
    user = await get_user_by_email(request_data.email)
    if not user:
        return {"message": "If the email exists, a password reset code has been sent"}

    reset_code = str(random.randint(100000, 999999))
    reset_code_expires = datetime.utcnow() + timedelta(minutes=15)

    await pool.execute(
        "UPDATE users SET reset_code = $1, reset_code_expires = $2 WHERE id = $3::uuid",
        reset_code, reset_code_expires, user.id,
    )

    background_tasks.add_task(
        send_password_reset_email,
        to_email=user.email,
        reset_code=reset_code,
        user_name=user.full_name,
    )

    return {"message": "If the email exists, a password reset code has been sent", "expires_in_minutes": 15}


@app.post("/api/auth/verify-reset-code")
async def verify_reset_code(request_data: VerifyResetCodeRequest):
    user = await get_user_by_email(request_data.email)
    if not user or not user.reset_code or not user.reset_code_expires:
        raise HTTPException(status_code=400, detail="Invalid email or reset code")
    if user.reset_code != request_data.code:
        raise HTTPException(status_code=400, detail="Invalid reset code")
    if datetime.utcnow() > user.reset_code_expires:
        raise HTTPException(status_code=400, detail="Reset code has expired. Please request a new one.")
    return {"message": "Reset code is valid", "valid": True}


@app.post("/api/auth/reset-password")
async def reset_password(request_data: ResetPasswordRequest):
    pool = get_pool()
    user = await get_user_by_email(request_data.email)
    if not user or not user.reset_code or not user.reset_code_expires:
        raise HTTPException(status_code=400, detail="Invalid email or reset code")
    if user.reset_code != request_data.code:
        raise HTTPException(status_code=400, detail="Invalid reset code")
    if datetime.utcnow() > user.reset_code_expires:
        raise HTTPException(status_code=400, detail="Reset code has expired. Please request a new one.")

    hashed_password = get_password_hash(request_data.new_password)
    await pool.execute(
        "UPDATE users SET hashed_password = $1, reset_code = NULL, reset_code_expires = NULL WHERE id = $2::uuid",
        hashed_password, user.id,
    )
    return {"message": "Password successfully reset"}


# ── User search ───────────────────────────────────────────────────────────────

@app.get("/api/users/search")
async def search_users(query: str, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    if not query or len(query) < 2:
        return []
    rows = await pool.fetch(
        """
        SELECT id, email, full_name, picture
        FROM users
        WHERE (email ILIKE $1 OR full_name ILIKE $1)
          AND is_active = true
          AND email != $2
        LIMIT 10
        """,
        f"%{query}%", current_user.email,
    )
    return [{"id": str(r["id"]), "email": r["email"], "full_name": r["full_name"], "picture": r["picture"]} for r in rows]


# ── Cloudinary ────────────────────────────────────────────────────────────────

@app.patch("/api/users/me/cloudinary")
async def update_cloudinary_settings(
    request: CloudinaryUpdateRequest,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()
    encrypted_api_key = encrypt_value(request.cloudinary_api_key)
    encrypted_api_secret = encrypt_value(request.cloudinary_api_secret)

    row = await pool.fetchrow(
        """
        UPDATE users
        SET cloudinary_cloud_name = $1,
            cloudinary_api_key    = $2,
            cloudinary_api_secret = $3
        WHERE id = $4::uuid
        RETURNING *
        """,
        request.cloudinary_cloud_name,
        encrypted_api_key,
        encrypted_api_secret,
        current_user.id,
    )

    creds = get_decrypted_cloudinary_credentials(dict(row))
    return {
        "message": "Cloudinary settings updated successfully",
        "user": {
            "id": str(row["id"]),
            "email": row["email"],
            "full_name": row["full_name"],
            "picture": row["picture"],
            "provider": row["provider"],
            **creds,
        },
    }


@app.post("/api/test-cloudinary", response_model=CloudinaryTestResponse)
async def test_cloudinary_credentials(request: CloudinaryTestRequest):
    try:
        if not request.cloudinary_cloud_name or not request.cloudinary_cloud_name.strip():
            return CloudinaryTestResponse(success=False, message="Cloud name is required")
        if not all(c.isalnum() or c in "-_" for c in request.cloudinary_cloud_name):
            return CloudinaryTestResponse(success=False, message="Cloud name can only contain letters, numbers, hyphens, and underscores")

        auth_string = f"{request.cloudinary_api_key}:{request.cloudinary_api_secret}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://api.cloudinary.com/v1_1/{request.cloudinary_cloud_name}/resources/image",
                headers={"Authorization": f"Basic {encoded_auth}"},
                params={"max_results": 1},
            )
            if response.status_code == 200:
                return CloudinaryTestResponse(success=True, message="Credentials verified successfully! ✓")
            elif response.status_code == 401:
                return CloudinaryTestResponse(success=False, message="Invalid API Key or Secret.")
            elif response.status_code == 404:
                return CloudinaryTestResponse(success=False, message="Cloud name not found.")
            else:
                return CloudinaryTestResponse(success=False, message=f"Cloudinary returned status {response.status_code}")
    except httpx.TimeoutException:
        return CloudinaryTestResponse(success=False, message="Connection timeout.")
    except Exception as e:
        return CloudinaryTestResponse(success=False, message=f"Test failed: {str(e)}")


# ── Folder CRUD ───────────────────────────────────────────────────────────────

@app.post("/api/folders", response_model=FolderInDB)
async def create_folder(folder: FolderCreate, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()

    # Duplicate name check
    existing = await pool.fetchrow(
        """
        SELECT id FROM folders
        WHERE user_id = $1::uuid AND name = $2
          AND ($3::uuid IS NULL AND parent_id IS NULL OR parent_id = $3::uuid)
        """,
        current_user.id, folder.name, folder.parent_id,
    )
    if existing:
        raise HTTPException(status_code=400, detail=f"A folder named '{folder.name}' already exists in this location")

    # Inherit shares from parent
    inherited_shares: List[str] = []
    if folder.parent_id:
        inherited_shares = await _get_folder_shared_with(pool, folder.parent_id)

    row = await pool.fetchrow(
        """
        INSERT INTO folders (user_id, name, parent_id, created_at)
        VALUES ($1::uuid, $2, $3::uuid, NOW())
        RETURNING *
        """,
        current_user.id, folder.name, folder.parent_id,
    )
    folder_id = str(row["id"])

    # Create share entries for inherited shares
    for email in inherited_shares:
        await pool.execute(
            """
            INSERT INTO folder_shares (folder_id, shared_by_user_id, shared_with_email, shared_at)
            VALUES ($1::uuid, $2::uuid, $3, NOW())
            ON CONFLICT (folder_id, shared_with_email) DO NOTHING
            """,
            folder_id, current_user.id, email,
        )

    return _folder_from_row(row, shared_with=inherited_shares)


@app.get("/api/folders", response_model=List[FolderInDB])
async def list_folders(current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    all_folders = []

    # Owned folders
    owned_rows = await pool.fetch(
        "SELECT * FROM folders WHERE user_id = $1::uuid ORDER BY created_at",
        current_user.id,
    )
    for row in owned_rows:
        fid = str(row["id"])
        shared_with = await _get_folder_shared_with(pool, fid)
        all_folders.append(_folder_from_row(row, shared_with=shared_with))

    # Folders shared with this user
    shared_rows = await pool.fetch(
        """
        SELECT f.*, u.email AS shared_by_email
        FROM folders f
        JOIN folder_shares fs ON fs.folder_id = f.id AND fs.shared_with_email = $1
        JOIN users u ON u.id = f.user_id
        WHERE f.user_id != $2::uuid
        ORDER BY f.created_at
        """,
        current_user.email.lower(), current_user.id,
    )
    for row in shared_rows:
        fid = str(row["id"])
        shared_with = await _get_folder_shared_with(pool, fid)
        all_folders.append(_folder_from_row(
            row,
            shared_with=shared_with,
            is_shared=True,
            shared_by=row["shared_by_email"],
            original_owner_id=str(row["user_id"]),
        ))

    logger.info(f"📁 {current_user.email}: {len(all_folders)} folders")
    return all_folders


@app.put("/api/folders/{folder_id}", response_model=FolderInDB)
async def update_folder(folder_id: str, folder: FolderUpdate, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()

    existing = await pool.fetchrow("SELECT * FROM folders WHERE id = $1::uuid", folder_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Folder not found")
    if str(existing["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can edit this folder")

    update_parts = []
    params = []
    idx = 1

    if folder.name is not None:
        update_parts.append(f"name = ${idx}")
        params.append(folder.name)
        idx += 1
    if folder.parent_id is not None or (folder.model_fields_set and "parent_id" in folder.model_fields_set):
        update_parts.append(f"parent_id = ${idx}::uuid")
        params.append(folder.parent_id)
        idx += 1

    if not update_parts:
        shared_with = await _get_folder_shared_with(pool, folder_id)
        return _folder_from_row(existing, shared_with=shared_with)

    params.append(folder_id)
    row = await pool.fetchrow(
        f"UPDATE folders SET {', '.join(update_parts)} WHERE id = ${idx}::uuid RETURNING *",
        *params,
    )
    shared_with = await _get_folder_shared_with(pool, folder_id)
    return _folder_from_row(row, shared_with=shared_with)


@app.delete("/api/folders/{folder_id}")
async def delete_folder(
    folder_id: str,
    background_tasks: BackgroundTasks,
    move_to_root: bool = True,
    destination_folder_id: Optional[str] = None,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()

    existing = await pool.fetchrow("SELECT * FROM folders WHERE id = $1::uuid", folder_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Folder not found")
    if str(existing["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can delete this folder")

    if move_to_root:
        target = destination_folder_id or existing.get("parent_id")
        target_param = str(target) if target else None

        # Move child folders up
        await pool.execute(
            "UPDATE folders SET parent_id = $1::uuid WHERE parent_id = $2::uuid",
            target_param, folder_id,
        )
        # Move notes in folder
        await pool.execute(
            "UPDATE notes SET folder_id = $1::uuid WHERE folder_id = $2::uuid",
            target_param, folder_id,
        )
        await pool.execute("DELETE FROM folders WHERE id = $1::uuid", folder_id)
        return {"message": "Folder deleted"}
    else:
        # Recursive delete using CTE
        await pool.execute(
            """
            WITH RECURSIVE descendants AS (
                SELECT id FROM folders WHERE id = $1::uuid
                UNION ALL
                SELECT f.id FROM folders f JOIN descendants d ON f.parent_id = d.id
            )
            DELETE FROM notes WHERE folder_id IN (SELECT id FROM descendants)
            """,
            folder_id,
        )
        await pool.execute(
            """
            WITH RECURSIVE descendants AS (
                SELECT id FROM folders WHERE id = $1::uuid
                UNION ALL
                SELECT f.id FROM folders f JOIN descendants d ON f.parent_id = d.id
            )
            DELETE FROM folders WHERE id IN (SELECT id FROM descendants)
            """,
            folder_id,
        )
        return {"message": "Folder and all contents deleted"}


@app.post("/api/folders/{folder_id}/share")
async def share_folder(
    folder_id: str,
    share_request: ShareNoteRequest,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()
    folder = await pool.fetchrow(
        "SELECT * FROM folders WHERE id = $1::uuid AND user_id = $2::uuid",
        folder_id, current_user.id,
    )
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")

    recipient_email = share_request.email.strip().lower()
    recipient = await get_user_by_email(recipient_email)

    # Get all descendant folder IDs via recursive CTE
    folder_ids_rows = await pool.fetch(
        """
        WITH RECURSIVE descendants AS (
            SELECT id FROM folders WHERE id = $1::uuid
            UNION ALL
            SELECT f.id FROM folders f JOIN descendants d ON f.parent_id = d.id
        )
        SELECT id FROM descendants
        """,
        folder_id,
    )
    all_folder_ids = [str(r["id"]) for r in folder_ids_rows]

    # Share all folders
    for fid in all_folder_ids:
        await pool.execute(
            """
            INSERT INTO folder_shares (folder_id, shared_by_user_id, shared_with_email, shared_at)
            VALUES ($1::uuid, $2::uuid, $3, NOW())
            ON CONFLICT (folder_id, shared_with_email) DO NOTHING
            """,
            fid, current_user.id, recipient_email,
        )

    # Get all notes in those folders and share them too
    if all_folder_ids:
        folder_uuid_list = [fid for fid in all_folder_ids]
        notes_rows = await pool.fetch(
            "SELECT id FROM notes WHERE folder_id = ANY($1::uuid[])",
            folder_uuid_list,
        )
        for note_row in notes_rows:
            await pool.execute(
                """
                INSERT INTO note_shares (note_id, shared_by_user_id, shared_with_email, shared_at)
                VALUES ($1::uuid, $2::uuid, $3, NOW())
                ON CONFLICT (note_id, shared_with_email) DO NOTHING
                """,
                str(note_row["id"]), current_user.id, recipient_email,
            )

    background_tasks.add_task(
        send_share_notification_email,
        to_email=recipient_email,
        shared_by_name=current_user.full_name or current_user.email,
        item_type="folder",
        item_title=folder["name"],
    )

    return {
        "message": f"Folder and contents shared with {recipient_email}",
        "is_new_user": recipient is None,
        "total_folders_shared": len(all_folder_ids),
    }


@app.get("/api/folders/{folder_id}/shares")
async def get_folder_shares(folder_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    folder = await pool.fetchrow("SELECT * FROM folders WHERE id = $1::uuid", folder_id)
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    if str(folder["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can view share details")

    rows = await pool.fetch(
        "SELECT * FROM folder_shares WHERE folder_id = $1::uuid", folder_id
    )
    shares = []
    for r in rows:
        user = await get_user_by_email(r["shared_with_email"])
        shares.append({
            "email": r["shared_with_email"],
            "full_name": user.full_name if user else None,
            "picture": user.picture if user else None,
            "has_account": user is not None,
            "shared_at": r["shared_at"],
        })
    return {"folder_id": folder_id, "folder_name": folder["name"], "shares": shares, "total_shares": len(shares)}


@app.post("/api/folders/{folder_id}/shares/{email}/resend")
async def resend_folder_share_notification(
    folder_id: str,
    email: str,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()
    folder = await pool.fetchrow("SELECT * FROM folders WHERE id = $1::uuid", folder_id)
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    if str(folder["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can resend share notifications")

    recipient_email = email.strip().lower()
    share = await pool.fetchrow(
        "SELECT id FROM folder_shares WHERE folder_id = $1::uuid AND shared_with_email = $2",
        folder_id, recipient_email,
    )
    if not share:
        raise HTTPException(status_code=400, detail="This folder is not shared with that email")

    background_tasks.add_task(
        send_share_notification_email,
        to_email=recipient_email,
        shared_by_name=current_user.full_name or current_user.email,
        item_type="folder",
        item_title=folder["name"],
    )
    return {"message": f"Share notification resent to {recipient_email}"}


@app.delete("/api/folders/{folder_id}/shares/{email}")
async def unshare_folder(
    folder_id: str,
    email: str,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()
    folder = await pool.fetchrow("SELECT * FROM folders WHERE id = $1::uuid", folder_id)
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    if str(folder["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can remove sharing")

    recipient_email = email.strip().lower()

    # Get all descendant folder IDs
    folder_ids_rows = await pool.fetch(
        """
        WITH RECURSIVE descendants AS (
            SELECT id FROM folders WHERE id = $1::uuid
            UNION ALL
            SELECT f.id FROM folders f JOIN descendants d ON f.parent_id = d.id
        )
        SELECT id FROM descendants
        """,
        folder_id,
    )
    all_folder_ids = [str(r["id"]) for r in folder_ids_rows]

    for fid in all_folder_ids:
        await pool.execute(
            "DELETE FROM folder_shares WHERE folder_id = $1::uuid AND shared_with_email = $2",
            fid, recipient_email,
        )

    # Unshare notes in those folders
    if all_folder_ids:
        notes_rows = await pool.fetch(
            "SELECT id FROM notes WHERE folder_id = ANY($1::uuid[])",
            all_folder_ids,
        )
        for note_row in notes_rows:
            await pool.execute(
                "DELETE FROM note_shares WHERE note_id = $1::uuid AND shared_with_email = $2",
                str(note_row["id"]), recipient_email,
            )

    return {"message": f"Folder access removed for {recipient_email}"}


# ── Notes CRUD ────────────────────────────────────────────────────────────────

@app.get("/api/notes", response_model=List[NoteInDB])
async def get_all_notes(current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    all_notes = []

    # Owned notes
    owned_rows = await pool.fetch(
        "SELECT * FROM notes WHERE user_id = $1::uuid ORDER BY updated_at DESC NULLS LAST",
        current_user.id,
    )
    for row in owned_rows:
        nid = str(row["id"])
        shared_with = await _get_note_shared_with(pool, nid)
        all_notes.append(_note_from_row(row, shared_with=shared_with))

    # Notes shared with this user
    shared_rows = await pool.fetch(
        """
        SELECT n.*, u.email AS shared_by_email
        FROM notes n
        JOIN note_shares ns ON ns.note_id = n.id AND ns.shared_with_email = $1
        JOIN users u ON u.id = n.user_id
        WHERE n.user_id != $2::uuid
        ORDER BY n.updated_at DESC NULLS LAST
        """,
        current_user.email.lower(), current_user.id,
    )
    for row in shared_rows:
        nid = str(row["id"])
        shared_with = await _get_note_shared_with(pool, nid)
        all_notes.append(_note_from_row(
            row,
            shared_with=shared_with,
            is_shared=True,
            shared_by=row["shared_by_email"],
            original_owner_id=str(row["user_id"]),
            original_owner_email=row["shared_by_email"],
        ))

    logger.info(f"📝 {current_user.email}: {len(all_notes)} notes total")
    return all_notes


@app.get("/api/notes/{note_id}", response_model=NoteInDB)
async def get_note(note_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    row = await pool.fetchrow("SELECT * FROM notes WHERE id = $1::uuid", note_id)
    if not row:
        raise HTTPException(status_code=404, detail="Note not found")

    is_owner = str(row["user_id"]) == current_user.id
    share = await pool.fetchrow(
        "SELECT id FROM note_shares WHERE note_id = $1::uuid AND shared_with_email = $2",
        note_id, current_user.email.lower(),
    )
    if not is_owner and not share:
        raise HTTPException(status_code=403, detail="You don't have permission to view this note")

    shared_with = await _get_note_shared_with(pool, note_id)
    return _note_from_row(row, shared_with=shared_with, is_shared=not is_owner)


@app.post("/api/notes", response_model=NoteInDB, status_code=status.HTTP_201_CREATED)
async def create_note(note: NoteCreate, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()

    # Duplicate title check
    existing = await pool.fetchrow(
        """
        SELECT id FROM notes
        WHERE user_id = $1::uuid AND title = $2
          AND ($3::uuid IS NULL AND folder_id IS NULL OR folder_id = $3::uuid)
        """,
        current_user.id, note.title, note.folder_id,
    )
    if existing:
        raise HTTPException(status_code=400, detail=f"A note titled '{note.title}' already exists in this location")

    row = await pool.fetchrow(
        """
        INSERT INTO notes (user_id, folder_id, title, content, created_at, updated_at)
        VALUES ($1::uuid, $2::uuid, $3, $4, NOW(), NOW())
        RETURNING *
        """,
        current_user.id, note.folder_id, note.title, note.content,
    )
    note_id = str(row["id"])

    # Inherit shares from folder
    inherited_shares: List[str] = []
    if note.folder_id:
        inherited_shares = await _get_folder_shared_with(pool, note.folder_id)
        for email in inherited_shares:
            await pool.execute(
                """
                INSERT INTO note_shares (note_id, shared_by_user_id, shared_with_email, shared_at)
                VALUES ($1::uuid, $2::uuid, $3, NOW())
                ON CONFLICT (note_id, shared_with_email) DO NOTHING
                """,
                note_id, current_user.id, email,
            )

    return _note_from_row(row, shared_with=inherited_shares)


@app.put("/api/notes/{note_id}", response_model=NoteInDB)
async def update_note(note_id: str, note_update: NoteUpdate, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()

    existing = await pool.fetchrow("SELECT * FROM notes WHERE id = $1::uuid", note_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Note not found")
    if str(existing["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can edit this note")

    update_parts = []
    params = []
    idx = 1

    if note_update.title is not None:
        update_parts.append(f"title = ${idx}")
        params.append(note_update.title)
        idx += 1
    if note_update.content is not None:
        update_parts.append(f"content = ${idx}")
        params.append(note_update.content)
        idx += 1
    if "folder_id" in (note_update.model_fields_set or {}):
        update_parts.append(f"folder_id = ${idx}::uuid")
        params.append(note_update.folder_id)
        idx += 1

    update_parts.append(f"updated_at = ${idx}")
    params.append(datetime.utcnow())
    idx += 1

    params.append(note_id)
    row = await pool.fetchrow(
        f"UPDATE notes SET {', '.join(update_parts)} WHERE id = ${idx}::uuid RETURNING *",
        *params,
    )

    shared_with = await _get_note_shared_with(pool, note_id)
    return _note_from_row(row, shared_with=shared_with)


@app.delete("/api/notes/{note_id}")
async def delete_note(
    note_id: str,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()

    existing = await pool.fetchrow("SELECT * FROM notes WHERE id = $1::uuid", note_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Note not found")
    if str(existing["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can delete this note")

    content = existing.get("content", "")
    if content:
        background_tasks.add_task(cleanup_note_images, content, current_user.id)

    await pool.execute("DELETE FROM notes WHERE id = $1::uuid", note_id)
    return {"message": "Note deleted successfully"}


@app.post("/api/notes/{note_id}/share")
async def share_note(
    note_id: str,
    share_request: ShareNoteRequest,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()
    note = await pool.fetchrow(
        "SELECT * FROM notes WHERE id = $1::uuid AND user_id = $2::uuid",
        note_id, current_user.id,
    )
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    recipient_email = share_request.email.strip().lower()
    recipient = await get_user_by_email(recipient_email)

    await pool.execute(
        """
        INSERT INTO note_shares (note_id, shared_by_user_id, shared_with_email, shared_at)
        VALUES ($1::uuid, $2::uuid, $3, NOW())
        ON CONFLICT (note_id, shared_with_email) DO NOTHING
        """,
        note_id, current_user.id, recipient_email,
    )

    background_tasks.add_task(
        send_share_notification_email,
        to_email=recipient_email,
        shared_by_name=current_user.full_name or current_user.email,
        item_type="note",
        item_title=note["title"],
    )

    return {"message": f"Note shared with {recipient_email}", "is_new_user": recipient is None}


@app.get("/api/notes/{note_id}/shares")
async def get_note_shares(note_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    note = await pool.fetchrow("SELECT * FROM notes WHERE id = $1::uuid", note_id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    if str(note["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can view share details")

    rows = await pool.fetch("SELECT * FROM note_shares WHERE note_id = $1::uuid", note_id)
    shares = []
    for r in rows:
        user = await get_user_by_email(r["shared_with_email"])
        shares.append({
            "email": r["shared_with_email"],
            "full_name": user.full_name if user else None,
            "picture": user.picture if user else None,
            "has_account": user is not None,
            "shared_at": r["shared_at"],
        })
    return {"note_id": note_id, "note_title": note["title"], "shares": shares, "total_shares": len(shares)}


@app.post("/api/notes/{note_id}/shares/{email}/resend")
async def resend_share_notification(
    note_id: str,
    email: str,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()
    note = await pool.fetchrow("SELECT * FROM notes WHERE id = $1::uuid", note_id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    if str(note["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can resend share notifications")

    recipient_email = email.strip().lower()
    share = await pool.fetchrow(
        "SELECT id FROM note_shares WHERE note_id = $1::uuid AND shared_with_email = $2",
        note_id, recipient_email,
    )
    if not share:
        raise HTTPException(status_code=400, detail="This note is not shared with that email")

    background_tasks.add_task(
        send_share_notification_email,
        to_email=recipient_email,
        shared_by_name=current_user.full_name or current_user.email,
        item_type="note",
        item_title=note["title"],
    )
    return {"message": f"Share notification resent to {recipient_email}"}


@app.delete("/api/notes/{note_id}/shares/{email}")
async def unshare_note(
    note_id: str,
    email: str,
    current_user: UserInDB = Depends(get_current_active_user),
):
    pool = get_pool()
    note = await pool.fetchrow("SELECT * FROM notes WHERE id = $1::uuid", note_id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    if str(note["user_id"]) != current_user.id:
        raise HTTPException(status_code=403, detail="Only the owner can remove sharing")

    recipient_email = email.strip().lower()
    await pool.execute(
        "DELETE FROM note_shares WHERE note_id = $1::uuid AND shared_with_email = $2",
        note_id, recipient_email,
    )
    return {"message": f"Sharing removed for {recipient_email}"}


# ── Chats ─────────────────────────────────────────────────────────────────────

@app.get("/api/chats", response_model=List[ChatInDB])
async def get_chats(current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    rows = await pool.fetch(
        "SELECT * FROM chats WHERE user_id = $1::uuid ORDER BY updated_at DESC NULLS LAST",
        current_user.id,
    )
    return [_chat_from_row(r) for r in rows]


@app.get("/api/chats/{chat_id}", response_model=ChatInDB)
async def get_chat(chat_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    row = await pool.fetchrow(
        "SELECT * FROM chats WHERE id = $1::uuid AND user_id = $2::uuid", chat_id, current_user.id
    )
    if not row:
        raise HTTPException(status_code=404, detail="Chat not found")
    return _chat_from_row(row)


@app.post("/api/chats", response_model=ChatInDB, status_code=status.HTTP_201_CREATED)
async def create_chat(chat: ChatCreate, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    messages_json = json.dumps([m.dict() for m in chat.messages], default=str)
    row = await pool.fetchrow(
        """
        INSERT INTO chats (user_id, note_id, title, messages, created_at, updated_at)
        VALUES ($1::uuid, $2::uuid, $3, $4::jsonb, NOW(), NOW())
        RETURNING *
        """,
        current_user.id, chat.note_id, chat.title, messages_json,
    )
    return _chat_from_row(row)


@app.put("/api/chats/{chat_id}", response_model=ChatInDB)
async def update_chat(chat_id: str, chat_update: ChatUpdate, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()

    update_parts = []
    params = []
    idx = 1

    if chat_update.title is not None:
        update_parts.append(f"title = ${idx}")
        params.append(chat_update.title)
        idx += 1
    if chat_update.messages is not None:
        messages_json = json.dumps([m.dict() if hasattr(m, "dict") else m for m in chat_update.messages], default=str)
        update_parts.append(f"messages = ${idx}::jsonb")
        params.append(messages_json)
        idx += 1

    update_parts.append(f"updated_at = ${idx}")
    params.append(datetime.utcnow())
    idx += 1

    params.extend([chat_id, current_user.id])
    row = await pool.fetchrow(
        f"UPDATE chats SET {', '.join(update_parts)} WHERE id = ${idx}::uuid AND user_id = ${idx+1}::uuid RETURNING *",
        *params,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Chat not found")
    return _chat_from_row(row)


@app.delete("/api/chats/{chat_id}")
async def delete_chat(chat_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    result = await pool.execute(
        "DELETE FROM chats WHERE id = $1::uuid AND user_id = $2::uuid", chat_id, current_user.id
    )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Chat not found")
    return {"message": "Chat deleted successfully"}


# ── AI Settings ───────────────────────────────────────────────────────────────

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

STEP 2 - Second Response (AFTER USER CONFIRMS):
- User says "yes" or "proceed" or "ok"
- THEN respond with "✅ Done! ..."
- THEN add COMMAND line
- ⚠️ WITHOUT THE COMMAND LINE, NOTHING HAPPENS!

Important:
- **CRITICAL**: The `COMMAND:` line MUST be included in your response **AFTER** the user confirms.
- **FORMAT**: Each command must be on its own line. **NEVER** wrap the command in markdown code blocks.
- **TITLES**: Note titles can be numeric (like "36"). Always treat them as strings in the JSON.
- Never use raw HTML tags like <p>, <ul>, etc. in content.
- **REMEMBER**: No COMMAND line = No action will happen. ALWAYS include it after confirmation!"""


@app.get("/api/settings", response_model=LLMSettingsInDB)
async def get_llm_settings(current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    row = await pool.fetchrow(
        "SELECT * FROM llm_settings WHERE user_id = $1::uuid", current_user.id
    )
    if row:
        return _llm_settings_from_row(row)

    # Create default settings
    row = await pool.fetchrow(
        """
        INSERT INTO llm_settings (user_id, providers, system_prompt, updated_at)
        VALUES ($1::uuid, '[]'::jsonb, $2, NOW())
        RETURNING *
        """,
        current_user.id, DEFAULT_SYSTEM_PROMPT,
    )
    return _llm_settings_from_row(row)


def _llm_settings_from_row(row) -> LLMSettingsInDB:
    d = dict(row)
    providers_raw = d.get("providers") or []
    if isinstance(providers_raw, str):
        providers_raw = json.loads(providers_raw)
    providers = [LLMProvider(**p) if isinstance(p, dict) else p for p in providers_raw]
    return LLMSettingsInDB(
        **{
            "_id": str(d["id"]),
            "providers": providers,
            "default_model": d.get("default_model"),
            "system_prompt": d.get("system_prompt"),
            "updated_at": d.get("updated_at"),
        }
    )


@app.put("/api/settings", response_model=LLMSettingsInDB)
async def update_llm_settings(settings: LLMSettings, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    providers = [p.dict() for p in settings.providers]
    if providers and not any(p.get("is_active") for p in providers):
        providers[0]["is_active"] = True

    row = await pool.fetchrow(
        """
        INSERT INTO llm_settings (user_id, providers, system_prompt, updated_at)
        VALUES ($1::uuid, $2::jsonb, $3, NOW())
        ON CONFLICT (user_id) DO UPDATE SET
            providers    = EXCLUDED.providers,
            system_prompt = EXCLUDED.system_prompt,
            updated_at   = NOW()
        RETURNING *
        """,
        current_user.id,
        json.dumps(providers),
        settings.system_prompt,
    )
    return _llm_settings_from_row(row)


# ── AI Chat ───────────────────────────────────────────────────────────────────

async def _get_llm_provider(current_user: UserInDB):
    """Fetch active LLM provider settings for user from Neon."""
    pool = get_pool()
    row = await pool.fetchrow(
        "SELECT * FROM llm_settings WHERE user_id = $1::uuid", current_user.id
    )
    if not row:
        return None, None, None, None, None

    providers_raw = row.get("providers") or []
    if isinstance(providers_raw, str):
        providers_raw = json.loads(providers_raw)

    if not providers_raw:
        return None, None, None, None, None

    active = [p for p in providers_raw if p.get("is_active")] or [providers_raw[0]]
    default_model = row.get("default_model")
    selected = next((p for p in active if p.get("name") == default_model), None) or active[0]

    use_global = selected.get("use_global_prompt", False)
    provider_prompt = (selected.get("system_prompt") or "").strip()
    global_prompt = (row.get("system_prompt") or "").strip()

    return selected, use_global, provider_prompt, global_prompt, providers_raw


async def _build_messages(request: AIRequest, current_user: UserInDB,
                          system_prompt: str) -> list:
    pool = get_pool()
    messages = [{"role": "system", "content": system_prompt}]

    if request.current_content:
        messages.append({"role": "system", "content": f"Current note content:\n\n{request.current_content}"})

    # Build folder/note structure for AI context
    folders_rows = await pool.fetch(
        "SELECT id, name, parent_id FROM folders WHERE user_id = $1::uuid", current_user.id
    )
    notes_rows = await pool.fetch(
        "SELECT id, title, folder_id FROM notes WHERE user_id = $1::uuid", current_user.id
    )
    folders_data = [dict(r) for r in folders_rows]
    notes_data = [dict(r) for r in notes_rows]

    def build_tree(parent_id=None, level=0):
        text = ""
        indent = "  " * level
        for f in [x for x in folders_data if str(x.get("parent_id") or "") == str(parent_id or "")]:
            text += f"{indent}📂 Folder: {f.get('name')}\n"
            for n in [x for x in notes_data if str(x.get("folder_id") or "") == str(f["id"])]:
                text += f"{indent}  📄 Note: {n.get('title')}\n"
            text += build_tree(str(f["id"]), level + 1)
        if parent_id is None:
            for n in [x for x in notes_data if not x.get("folder_id")]:
                text += f"📄 Note: {n.get('title')}\n"
        return text

    structure = build_tree()
    messages.append({"role": "system", "content": "CRITICAL_CONTEXT: CURRENT_STRUCTURE\n" + (structure or "(No folders or notes yet)\n")})

    if request.messages:
        for msg in request.messages:
            if "role" in msg and "content" in msg:
                messages.append({"role": msg["role"], "content": msg["content"]})
    else:
        messages.append({"role": "user", "content": request.message})

    return messages


def _build_api_config(provider_type: str, api_key: str, model: str, messages: list, stream: bool = False):
    """Return (url, headers, payload) for the given LLM provider."""
    if provider_type == "openai":
        return (
            "https://api.openai.com/v1/chat/completions",
            {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            {"model": model, "messages": messages, "temperature": 0.7, **({"stream": True} if stream else {})},
        )
    elif provider_type == "anthropic":
        sys_content = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        user_msgs = [m for m in messages if m["role"] != "system"]
        return (
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
            {"model": model, "messages": user_msgs, "system": sys_content, "max_tokens": 2000, **({"stream": True} if stream else {})},
        )
    elif provider_type == "gemini":
        gemini_contents = []
        system_instruction = None
        for m in messages:
            if m["role"] == "system":
                system_instruction = {"parts": [{"text": m["content"]}]}
            else:
                role = "user" if m["role"] == "user" else "model"
                gemini_contents.append({"role": role, "parts": [{"text": m["content"]}]})
        suffix = ":streamGenerateContent?alt=sse&" if stream else ":generateContent?"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}{suffix}key={api_key}"
        payload = {"contents": gemini_contents, "generationConfig": {"temperature": 0.7}}
        if system_instruction:
            payload["systemInstruction"] = system_instruction
        return url, {"Content-Type": "application/json"}, payload
    elif provider_type == "ollama":
        return (
            f"{api_key}/api/chat",
            {"Content-Type": "application/json"},
            {"model": model, "messages": messages, "stream": stream},
        )
    else:  # openrouter
        return (
            "https://openrouter.ai/api/v1/chat/completions",
            {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
             "HTTP-Referer": "https://mindflow.ai", "X-Title": "MindFlow AI"},
            {"model": model, "messages": messages, "temperature": 0.7, "max_tokens": 2000, **({"stream": True} if stream else {})},
        )


@app.post("/api/ai/chat", response_model=AIResponse)
async def ai_chat(request: AIRequest, current_user: UserInDB = Depends(get_current_active_user)):
    selected, use_global, provider_prompt, global_prompt, _ = await _get_llm_provider(current_user)

    if not selected:
        return AIResponse(message="AI assistant is not configured. Please add an LLM provider in Settings (⚙️ icon).")

    api_key = selected.get("api_key")
    provider_type = selected.get("provider", "openrouter")
    model = selected.get("model")

    if not model:
        return AIResponse(message=f"Model not configured for '{selected.get('name')}'. Please update it in Settings.")
    if not api_key:
        return AIResponse(message=f"API key not configured for '{selected.get('name')}'. Please add it in Settings.")

    if request.edit_mode:
        system_prompt = "You are a helpful AI assistant that edits note documents.\n\nIMPORTANT: Your response will REPLACE the entire note content. Return the complete, updated note with proper markdown formatting."
    else:
        system_prompt = DEFAULT_SYSTEM_PROMPT

    if use_global and global_prompt:
        system_prompt = global_prompt
    elif provider_prompt:
        system_prompt = provider_prompt

    messages = await _build_messages(request, current_user, system_prompt)

    try:
        url, headers, payload = _build_api_config(provider_type, api_key, model, messages)
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=60.0)
            if response.status_code != 200:
                logger.error(f"LLM error {provider_type}: {response.status_code} {response.text}")
                try:
                    err = response.json().get("error", {})
                    msg = err.get("message", "") if isinstance(err, dict) else str(err)
                    if "credits" in msg.lower():
                        msg = "⚠️ Insufficient credits. Please add credits to your AI provider or switch providers in Settings."
                    elif "rate limit" in msg.lower():
                        msg = "⚠️ Rate limit exceeded. Please wait and try again."
                    else:
                        msg = f"⚠️ {msg[:150]}" if msg else "AI service error."
                except Exception:
                    msg = "AI service error. Please try again."
                raise HTTPException(status_code=response.status_code, detail=msg)

            result = response.json()
            if provider_type == "anthropic":
                ai_message = result["content"][0]["text"]
            elif provider_type == "gemini":
                ai_message = result["candidates"][0]["content"]["parts"][0]["text"]
            elif provider_type == "ollama":
                ai_message = result["message"]["content"]
            else:
                ai_message = result["choices"][0]["message"]["content"]

        updated_content = ai_message if request.edit_mode else None
        return AIResponse(message=ai_message, updated_content=updated_content)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI Chat Error: {e}")
        return AIResponse(message=f"Sorry, I encountered an error: {str(e)}. Please try again.")


@app.post("/api/ai/chat/stream")
async def ai_chat_stream(request: AIRequest, current_user: UserInDB = Depends(get_current_active_user)):
    selected, use_global, provider_prompt, global_prompt, _ = await _get_llm_provider(current_user)

    async def error_stream(msg):
        yield f"data: {json.dumps({'error': msg})}\n\n"
        yield "data: [DONE]\n\n"

    if not selected:
        return StreamingResponse(error_stream("AI assistant is not configured."), media_type="text/event-stream")

    api_key = selected.get("api_key")
    provider_type = selected.get("provider", "openrouter")
    model = selected.get("model")

    if not model or not api_key:
        return StreamingResponse(error_stream("Model or API key not configured."), media_type="text/event-stream")

    if request.edit_mode:
        system_prompt = "You are a helpful AI assistant that edits note documents. Return the FULL updated note content with proper markdown formatting."
    else:
        system_prompt = DEFAULT_SYSTEM_PROMPT

    if use_global and global_prompt:
        system_prompt = global_prompt
    elif provider_prompt:
        system_prompt = provider_prompt

    messages = await _build_messages(request, current_user, system_prompt)
    url, headers, payload = _build_api_config(provider_type, api_key, model, messages, stream=True)

    async def stream_response():
        try:
            async with httpx.AsyncClient() as client:
                if provider_type in ("openai", "openrouter"):
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line.startswith("data: "):
                                data = line[6:]
                                if data == "[DONE]":
                                    yield "data: [DONE]\n\n"
                                    break
                                try:
                                    chunk = json.loads(data)
                                    content = chunk.get("choices", [{}])[0].get("delta", {}).get("content")
                                    if content:
                                        yield f"data: {json.dumps({'content': content})}\n\n"
                                except json.JSONDecodeError:
                                    pass

                elif provider_type == "anthropic":
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line.startswith("data: "):
                                try:
                                    chunk = json.loads(line[6:])
                                    if chunk.get("type") == "content_block_delta":
                                        content = chunk.get("delta", {}).get("text", "")
                                        if content:
                                            yield f"data: {json.dumps({'content': content})}\n\n"
                                    elif chunk.get("type") == "message_stop":
                                        yield "data: [DONE]\n\n"
                                except json.JSONDecodeError:
                                    pass

                elif provider_type == "gemini":
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line.startswith("data: "):
                                try:
                                    chunk = json.loads(line[6:])
                                    for part in chunk.get("candidates", [{}])[0].get("content", {}).get("parts", []):
                                        if part.get("text"):
                                            yield f"data: {json.dumps({'content': part['text']})}\n\n"
                                except json.JSONDecodeError:
                                    pass
                    yield "data: [DONE]\n\n"

                elif provider_type == "ollama":
                    async with client.stream("POST", url, headers=headers, json=payload, timeout=120.0) as resp:
                        async for line in resp.aiter_lines():
                            if line:
                                try:
                                    chunk = json.loads(line)
                                    content = chunk.get("message", {}).get("content")
                                    if content:
                                        yield f"data: {json.dumps({'content': content})}\n\n"
                                    if chunk.get("done"):
                                        yield "data: [DONE]\n\n"
                                except json.JSONDecodeError:
                                    pass

        except Exception as e:
            logger.error(f"Streaming error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        stream_response(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


# ── LLM test ──────────────────────────────────────────────────────────────────

@app.post("/api/test-llm-connection", response_model=TestLLMConnectionResponse)
async def test_llm_connection(request: TestLLMConnectionRequest, current_user: UserInDB = Depends(get_current_active_user)):
    provider_configs = {
        "openrouter": {"url": "https://openrouter.ai/api/v1/chat/completions", "headers": {"Authorization": f"Bearer {request.api_key}", "Content-Type": "application/json"}},
        "openai": {"url": "https://api.openai.com/v1/chat/completions", "headers": {"Authorization": f"Bearer {request.api_key}", "Content-Type": "application/json"}},
        "anthropic": {"url": "https://api.anthropic.com/v1/messages", "headers": {"x-api-key": request.api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}},
        "gemini": {"url": f"https://generativelanguage.googleapis.com/v1beta/models/{request.model}:generateContent?key={request.api_key}", "headers": {"Content-Type": "application/json"}},
        "ollama": {"url": f"{request.api_key}/api/chat", "headers": {"Content-Type": "application/json"}},
    }

    config = provider_configs.get(request.provider)
    if not config:
        return TestLLMConnectionResponse(success=False, message=f"Provider '{request.provider}' is not supported", error_type="unsupported_provider")

    if request.provider == "anthropic":
        payload = {"model": request.model, "messages": [{"role": "user", "content": "test"}], "max_tokens": 5}
    elif request.provider == "gemini":
        payload = {"contents": [{"parts": [{"text": "test"}]}]}
    elif request.provider == "ollama":
        payload = {"model": request.model, "messages": [{"role": "user", "content": "test"}], "stream": False}
    else:
        payload = {"model": request.model, "messages": [{"role": "user", "content": "test"}], "max_tokens": 5}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(config["url"], headers=config["headers"], json=payload, timeout=15.0)
            if response.status_code == 200:
                return TestLLMConnectionResponse(success=True, message=f"✅ Successfully connected to {request.model}")
            try:
                error_data = response.json() if response.text else {}
                error_msg = (error_data.get("error") or {}).get("message") or error_data.get("message") or f"HTTP {response.status_code}"
                return TestLLMConnectionResponse(success=False, message=f"API Error: {error_msg}")
            except Exception:
                return TestLLMConnectionResponse(success=False, message=f"API Error: {response.status_code}")
    except httpx.TimeoutException:
        return TestLLMConnectionResponse(success=False, message="Connection timed out.")
    except Exception as e:
        return TestLLMConnectionResponse(success=False, message=f"Unexpected error: {str(e)}")


# ── Cloudinary image management ───────────────────────────────────────────────

@app.get("/api/cloudinary/images")
async def list_cloudinary_images(current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    notes = await pool.fetch("SELECT id, title, content FROM notes WHERE user_id = $1::uuid", current_user.id)

    cloudinary_pattern = r'https://res\.cloudinary\.com/[^"\')\s]+'
    image_usage: dict = {}

    for note in notes:
        content = note.get("content", "")
        for img_url in re.findall(cloudinary_pattern, content):
            if img_url not in image_usage:
                image_usage[img_url] = []
            image_usage[img_url].append({"note_id": str(note["id"]), "note_title": note.get("title", "Untitled")})

    images_list = []
    for url, usage in image_usage.items():
        m = re.search(r'/upload/(?:v\d+/)?(.+?)(?:\.[^.]+)?$', url)
        images_list.append({"url": url, "public_id": m.group(1) if m else "unknown", "usage_count": len(usage), "used_in_notes": usage})

    return {"total_images": len(images_list), "images": sorted(images_list, key=lambda x: x["usage_count"], reverse=True)}


@app.delete("/api/cloudinary/image")
async def delete_cloudinary_image(image_url: str, current_user: UserInDB = Depends(get_current_active_user)):
    pool = get_pool()
    user_row = await pool.fetchrow("SELECT * FROM users WHERE id = $1::uuid", current_user.id)
    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")

    creds = get_decrypted_cloudinary_credentials(dict(user_row))
    if not creds.get("cloudinary_cloud_name"):
        raise HTTPException(status_code=400, detail="Cloudinary not configured")

    m = re.search(r'/upload/(?:v\d+/)?(.+?)(?:\.[^.]+)?$', image_url)
    if not m:
        raise HTTPException(status_code=400, detail="Invalid Cloudinary URL")

    public_id = m.group(1)
    auth_string = f"{creds['cloudinary_api_key']}:{creds['cloudinary_api_secret']}"
    encoded_auth = base64.b64encode(auth_string.encode()).decode()

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.request(
            "DELETE",
            f"https://api.cloudinary.com/v1_1/{creds['cloudinary_cloud_name']}/resources/image/upload",
            headers={"Authorization": f"Basic {encoded_auth}"},
            json={"public_ids": [public_id]},
        )
        if response.status_code in [200, 404]:
            return {"success": True, "message": "Image deleted from Cloudinary", "public_id": public_id}
        return {"success": False, "message": f"Cloudinary API error: {response.status_code}"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
