from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from bson import ObjectId

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")

class NoteBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    content: str = ""
    folder_id: Optional[str] = None
    shared_with: List[str] = []  # List of emails
    owner_id: Optional[str] = None # To track ownership explicitly if needed, though usually implicit via user_id query
    
class NoteCreate(NoteBase):
    pass

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    folder_id: Optional[str] = None

class NoteInDB(NoteBase):
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    # Shared note fields
    is_shared: bool = False
    original_note_id: Optional[str] = None  # ID of the original note if this is a shared copy
    original_owner_id: Optional[str] = None
    original_owner_email: Optional[str] = None
    shared_by: Optional[str] = None  # Email of who shared
    shared_by_name: Optional[str] = None
    shared_at: Optional[datetime] = None
    share_history: List[dict] = []  # History of shares for owner's view
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}
        arbitrary_types_allowed = True

class FolderBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    parent_id: Optional[str] = None  # For nested folders
    shared_with: List[str] = []  # List of emails
    owner_id: Optional[str] = None

class FolderCreate(FolderBase):
    pass

class FolderUpdate(BaseModel):
    name: Optional[str] = None
    parent_id: Optional[str] = None

class FolderInDB(FolderBase):
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    user_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    # Shared folder fields
    is_shared: bool = False
    shared_by: Optional[str] = None  # Email of who shared
    original_owner_id: Optional[str] = None
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}
        arbitrary_types_allowed = True

class ChatMessage(BaseModel):
    role: str  # 'user' or 'assistant'
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
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}
        arbitrary_types_allowed = True

class LLMProvider(BaseModel):
    name: str = "Default Provider"
    provider: str  # 'openai', 'gemini', 'anthropic', etc.
    api_key: str
    model: Optional[str] = None
    is_active: bool = False
    system_prompt: Optional[str] = None  # Custom system prompt for this provider
    use_global_prompt: bool = False  # If true, use global prompt instead of provider prompt
    tested: bool = False  # Tracks if connection has been tested successfully

class LLMSettings(BaseModel):
    providers: List[LLMProvider] = []
    default_model: Optional[str] = None
    system_prompt: Optional[str] = None  # Global system prompt
    
class LLMSettingsInDB(LLMSettings):
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}
        arbitrary_types_allowed = True

class AIRequest(BaseModel):
    message: str
    current_content: str = ""
    edit_mode: bool = False
    messages: Optional[List[dict]] = None


class AIResponse(BaseModel):
    message: str
    updated_content: Optional[str] = None

class User(BaseModel):
    email: str
    full_name: Optional[str] = None
    picture: Optional[str] = None
    provider: str = "email"  # 'email' or 'google'
    hashed_password: Optional[str] = None  # Only for email auth
    refresh_tokens: List[str] = []  # Store active refresh tokens
    reset_code: Optional[str] = None  # 6-digit reset code
    reset_code_expires: Optional[datetime] = None  # Expiry time for reset code
    is_active: bool = True
    mongodb_connection_string: Optional[str] = None  # User's own MongoDB cluster
    has_database: bool = False  # Whether user has configured their database
    notes_count: int = 0  # Track number of notes created by user
    # Cloudinary configuration for image uploads
    cloudinary_cloud_name: Optional[str] = None
    cloudinary_api_key: Optional[str] = None
    cloudinary_api_secret: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserInDB(User):
    id: str = Field(default_factory=lambda: str(ObjectId()), alias="_id")
    
    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}
        arbitrary_types_allowed = True

class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    mongodb_connection_string: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

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

class ForgotPasswordRequest(BaseModel):
    email: str

class VerifyResetCodeRequest(BaseModel):
    email: str
    code: str

class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str

class ShareNoteRequest(BaseModel):
    email: str

class MongoDBConnectionRequest(BaseModel):
    connection_string: str

class MongoDBConnectionResponse(BaseModel):
    success: bool
    message: str

class TestLLMConnectionRequest(BaseModel):
    provider: str
    api_key: str
    model: str

class TestLLMConnectionResponse(BaseModel):
    success: bool
    message: str
    error_type: Optional[str] = None

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
