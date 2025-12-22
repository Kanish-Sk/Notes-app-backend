# App Directory

This directory contains the core application modules.

## Contents:

- `auth.py` - Authentication and authorization logic
- `database.py` - Main database connection handling
- `email_utils.py` - Email sending utilities (Gmail API)
- `logger.py` - Logging configuration
- `models.py` - Pydantic models and schemas
- `user_database.py` - User-specific database handling

## Architecture:

All core application logic is imported from this directory using the `app.` prefix in `main.py`.
