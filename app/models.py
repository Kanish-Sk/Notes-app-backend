from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import uuid


# ── Notes ─────────────────────────────────────────────────────────────────────

class NoteBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    content: str = ""
    folder_id: Optional[str] = None
    shared_with: List[str] = []
    owner_id: Optional[str] = None


class NoteCreate(NoteBase):
    pass


class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    folder_id: Optional[str] = None


class NoteInDB(NoteBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    user_id: Optional[str] = None
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    is_shared: bool = False
    original_note_id: Optional[str] = None
    original_owner_id: Optional[str] = None
    original_owner_email: Optional[str] = None
    shared_by: Optional[str] = None
    shared_by_name: Optional[str] = None
    shared_at: Optional[datetime] = None
    share_history: List[dict] = []

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True


# ── Folders ───────────────────────────────────────────────────────────────────

class FolderBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    parent_id: Optional[str] = None
    shared_with: List[str] = []
    owner_id: Optional[str] = None


class FolderCreate(FolderBase):
    pass


class FolderUpdate(BaseModel):
    name: Optional[str] = None
    parent_id: Optional[str] = None


class FolderInDB(FolderBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    user_id: str = ""
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    is_shared: bool = False
    shared_by: Optional[str] = None
    original_owner_id: Optional[str] = None

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True


# ── Chats ─────────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ChatBase(BaseModel):
    title: str = "New Chat"
    messages: List[ChatMessage] = []
    note_id: Optional[str] = None


class ChatCreate(ChatBase):
    pass


class ChatUpdate(BaseModel):
    title: Optional[str] = None
    messages: Optional[List[ChatMessage]] = None


class ChatInDB(ChatBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    user_id: Optional[str] = None
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True


# ── LLM Settings ──────────────────────────────────────────────────────────────

class LLMProvider(BaseModel):
    name: str = "Default Provider"
    provider: str
    api_key: str
    model: Optional[str] = None
    is_active: bool = False
    system_prompt: Optional[str] = None
    use_global_prompt: bool = False
    tested: bool = False


class LLMSettings(BaseModel):
    providers: List[LLMProvider] = []
    default_model: Optional[str] = None
    system_prompt: Optional[str] = None


class LLMSettingsInDB(LLMSettings):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True


# ── AI ────────────────────────────────────────────────────────────────────────

class AIRequest(BaseModel):
    message: str
    current_content: str = ""
    edit_mode: bool = False
    messages: Optional[List[dict]] = None


class AIResponse(BaseModel):
    message: str
    updated_content: Optional[str] = None


# ── Users ─────────────────────────────────────────────────────────────────────

class User(BaseModel):
    email: str
    full_name: Optional[str] = None
    picture: Optional[str] = None
    provider: str = "email"
    hashed_password: Optional[str] = None
    refresh_tokens: List[str] = []
    reset_code: Optional[str] = None
    reset_code_expires: Optional[datetime] = None
    is_active: bool = True
    cloudinary_cloud_name: Optional[str] = None
    cloudinary_api_key: Optional[str] = None    # stored encrypted
    cloudinary_api_secret: Optional[str] = None  # stored encrypted
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)


class UserInDB(User):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True


class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


# ── Auth tokens ───────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class TokenData(BaseModel):
    email: Optional[str] = None


class RefreshTokenData(BaseModel):
    refresh_token: str


class GoogleAuthRequest(BaseModel):
    credential: str


# ── Password reset ────────────────────────────────────────────────────────────

class ForgotPasswordRequest(BaseModel):
    email: str


class VerifyResetCodeRequest(BaseModel):
    email: str
    code: str


class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str


# ── Sharing ───────────────────────────────────────────────────────────────────

class ShareNoteRequest(BaseModel):
    email: str


# ── LLM connection test ───────────────────────────────────────────────────────

class TestLLMConnectionRequest(BaseModel):
    provider: str
    api_key: str
    model: str


class TestLLMConnectionResponse(BaseModel):
    success: bool
    message: str
    error_type: Optional[str] = None


# ── Cloudinary ────────────────────────────────────────────────────────────────

class CloudinaryTestRequest(BaseModel):
    cloudinary_cloud_name: str
    cloudinary_api_key: str
    cloudinary_api_secret: str


class CloudinaryTestResponse(BaseModel):
    success: bool
    message: str


class CloudinaryUpdateRequest(BaseModel):
    cloudinary_cloud_name: str
    cloudinary_api_key: str
    cloudinary_api_secret: str
