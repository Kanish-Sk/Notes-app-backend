# Notes App - Backend API

FastAPI backend for the AI-powered note-taking application.

## 🚀 Tech Stack

- **FastAPI** - Modern Python web framework
- **MongoDB** with Motor - Async database driver
- **JWT** - Authentication
- **Google OAuth** - Social login
- **OpenRouter** - AI integration
- **SMTP** - Email notifications
- **Cryptography** - Connection string encryption

## 📋 Prerequisites

- Python 3.8+
- MongoDB Atlas account
- Google OAuth credentials
- OpenRouter API key
- Gmail account (for SMTP)

## 🛠️ Local Setup

### 1. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Environment Variables

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

**Required Variables:**

```env
# MongoDB
MONGODB_URL=mongodb+srv://user:pass@cluster.mongodb.net/
DATABASE_NAME=notes_app

# Encryption (generate with command below)
DB_ENCRYPTION_KEY=your_32_byte_key

# OpenRouter AI
OPENROUTER_API_KEY=your_openrouter_key

# JWT (generate with command below)
JWT_SECRET_KEY=your_jwt_secret
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=10080
REFRESH_TOKEN_EXPIRE_DAYS=30

# Google OAuth
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REDIRECT_URI=http://localhost:5173/auth/google/callback

# SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM_EMAIL=your_email@gmail.com
SMTP_FROM_NAME=NotesApp
```

### 4. Generate Keys

```bash
# Encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# JWT secret
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### 5. Run the Server

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API will be available at `http://localhost:8000`

## 📚 API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🗂️ Project Structure

```
backend/
├── main.py              # FastAPI application
├── models.py            # Pydantic models
├── auth.py              # Authentication logic
├── database.py          # MongoDB connection
├── user_database.py     # Multi-tenant DB management
├── email_utils.py       # Email functionality
├── requirements.txt     # Dependencies
├── .env.example         # Environment template
└── .gitignore          # Git ignore rules
```

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/google` - Google OAuth login
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user

### Notes
- `GET /api/notes` - Get all notes
- `POST /api/notes` - Create note
- `GET /api/notes/{id}` - Get note by ID
- `PUT /api/notes/{id}` - Update note
- `DELETE /api/notes/{id}` - Delete note
- `POST /api/notes/{id}/share` - Share note

### Folders
- `GET /api/folders` - Get all folders
- `POST /api/folders` - Create folder
- `PUT /api/folders/{id}` - Update folder
- `DELETE /api/folders/{id}` - Delete folder

### AI
- `POST /api/ai/chat` - Chat with AI assistant

### Settings
- `GET /api/settings` - Get user settings
- `PUT /api/settings` - Update settings

### MongoDB
- `POST /api/verify-mongodb` - Verify connection string
- `POST /api/user/update-database` - Update user database

### Statistics
- `GET /api/stats` - Get app statistics

## 🌐 Deployment (Render)

### 1. Configuration

```
Runtime: Python 3
Build Command: pip install -r requirements.txt
Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT
```

### 2. Environment Variables

Add all variables from `.env` in Render dashboard.

**Important:** Update `GOOGLE_REDIRECT_URI` to your production URL:
```
GOOGLE_REDIRECT_URI=https://your-frontend.netlify.app/auth/google/callback
```

### 3. CORS

Update `main.py` with your frontend URL:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-frontend.netlify.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## 🔧 MongoDB Atlas Setup

1. Create cluster at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Create database user
3. Whitelist IP: `0.0.0.0/0` (for Render)
4. Get connection string
5. Add to `MONGODB_URL` environment variable

## 🔐 Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project
3. Enable Google+ API
4. Create OAuth Client ID
5. Add redirect URIs:
   - `http://localhost:5173/auth/google/callback` (dev)
   - `https://your-frontend.netlify.app/auth/google/callback` (prod)
6. Copy Client ID and Secret

## 🧪 Testing

```bash
# Run tests (if available)
pytest

# Test API endpoints
curl http://localhost:8000/api/stats
```

## 📝 Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| MONGODB_URL | Yes | MongoDB connection string |
| DATABASE_NAME | Yes | Database name |
| DB_ENCRYPTION_KEY | Yes | Fernet encryption key |
| OPENROUTER_API_KEY | Yes | OpenRouter API key |
| JWT_SECRET_KEY | Yes | JWT signing secret |
| GOOGLE_CLIENT_ID | Yes | Google OAuth client ID |
| GOOGLE_CLIENT_SECRET | Yes | Google OAuth secret |
| GOOGLE_REDIRECT_URI | Yes | OAuth redirect URL |
| SMTP_USER | Yes | Email for SMTP |
| SMTP_PASSWORD | Yes | Email app password |

## 🐛 Troubleshooting

**MongoDB Connection Failed:**
- Verify connection string format
- Check IP whitelist in Atlas
- Verify database user credentials

**Google OAuth Not Working:**
- Check redirect URI matches exactly
- Verify credentials are correct
- Wait 5 minutes after changing OAuth settings

**SMTP Errors:**
- Use Gmail App Password, not regular password
- Enable 2FA on Google account first
- Verify SMTP settings

## 📄 License

MIT License - see LICENSE file for details

## 👤 Author

**Kanish** - [kanishshivan@gmail.com](mailto:kanishshivan@gmail.com)
