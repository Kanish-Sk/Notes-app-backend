# Backend Folder Structure

The backend has been restructured for better organization and maintainability.

## Directory Structure

```
backend/
├── app/                    # Core application code
│   ├── auth.py            # Authentication & authorization
│   ├── database.py        # Main database connection
│   ├── email_utils.py     # Email sending (Gmail API)
│   ├── logger.py          # Logging configuration
│   ├── models.py          # Pydantic models & schemas
│   └── user_database.py   # User-specific database handling
│
├── scripts/               # Utility & maintenance scripts
│   ├── generate_gmail_token.py  # Gmail OAuth token generation
│   ├── migrate_folder_shares.py # Database migration scripts
│   ├── fix_*.py                 # Fix scripts
│   ├── patch_*.py               # Patch scripts
│   └── show_llm_settings.py     # Display LLM settings
│
├── tests/                 # Test & diagnostic scripts
│   ├── check_*.py         # Diagnostic scripts
│   ├── test_*.py          # Test scripts
│   └── verify_share.py    # Sharing verification
│
├── utils/                 # Future utility modules
│
├── main.py               # FastAPI application entry point
├── requirements.txt      # Python dependencies
├── .env                  # Environment variables (not in git)
├── .env.example          # Example environment variables
└── README.md             # Project documentation
```

## Key Changes

1. **app/** - All core modules moved here with `app.` import prefix
2. **scripts/** - Administrative and setup scripts
3. **tests/** - All test and diagnostic scripts
4. **utils/** - Reserved for future utility modules

## Import Changes

All imports in `main.py` now use the `app.` prefix:

```python
from app.models import UserCreate, NoteCreate, ...
from app.auth import get_current_user, ...
from app.database import get_database
```

## Running Scripts

### Tests:
```bash
python tests/check_shared_folders.py
python tests/test_folder_share.py
```

### Scripts:
```bash
python scripts/generate_gmail_token.py
python scripts/migrate_folder_shares.py
```

## Benefits

- ✅ **Better Organization** - Clear separation of concerns
- ✅ **Easier Navigation** - Find files quickly
- ✅ **Scalability** - Easy to add new modules
- ✅ **Maintainability** - READMEs in each directory
