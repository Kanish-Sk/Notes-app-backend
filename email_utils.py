import os
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_gmail_service():
    """Get Gmail API service"""
    creds = None
    token_file = os.getenv('GMAIL_TOKEN_FILE', 'token.json')
    credentials_file = os.getenv('GMAIL_CREDENTIALS_FILE', 'credentials.json')
    
    # The file token.json stores the user's access and refresh tokens
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(credentials_file):
                raise FileNotFoundError(
                    f"Gmail credentials file '{credentials_file}' not found. "
                    "Please download OAuth 2.0 credentials from Google Cloud Console."
                )
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save the credentials for the next run
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
    
    return build('gmail', 'v1', credentials=creds)

def create_message(to_email, subject, html_content):
    """Create a message for an email"""
    from_email = os.getenv('GMAIL_FROM_EMAIL', 'noreply@example.com')
    from_name = os.getenv('GMAIL_FROM_NAME', 'NotesApp')
    
    message = MIMEMultipart('alternative')
    message['to'] = to_email
    message['from'] = f"{from_name} <{from_email}>"
    message['subject'] = subject
    
    # Add HTML part
    html_part = MIMEText(html_content, 'html')
    message.attach(html_part)
    
    # Encode the message
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    return {'raw': raw_message}

async def send_email(to_email: str, subject: str, html_content: str) -> bool:
    """Send an email using Gmail API"""
    try:
        service = get_gmail_service()
        message = create_message(to_email, subject, html_content)
        
        # Send the message
        service.users().messages().send(userId='me', body=message).execute()
        print(f"✅ Email sent successfully to {to_email}")
        return True
        
    except HttpError as error:
        print(f"❌ Gmail API error: {error}")
        return False
    except FileNotFoundError as error:
        print(f"❌ {error}")
        return False
    except Exception as error:
        print(f"❌ Error sending email: {error}")
        return False

async def send_password_reset_email(email: str, code: str) -> bool:
    """Send password reset code email"""
    subject = "Reset Your Password - NotesApp"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f7fa;">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f5f7fa; padding: 40px 20px;">
            <tr>
                <td align="center">
                    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                        <!-- Header -->
                        <tr>
                            <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                                <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">
                                    🔐 Password Reset
                                </h1>
                            </td>
                        </tr>
                        
                        <!-- Content -->
                        <tr>
                            <td style="padding: 40px 30px;">
                                <p style="margin: 0 0 20px; color: #2d3748; font-size: 16px; line-height: 1.6;">
                                    Hello,
                                </p>
                                <p style="margin: 0 0 20px; color: #2d3748; font-size: 16px; line-height: 1.6;">
                                    We received a request to reset your password. Use the code below to reset your password:
                                </p>
                                
                                <!-- Code Box -->
                                <div style="background-color: #f7fafc; border: 2px dashed #cbd5e0; border-radius: 12px; padding: 30px; text-align: center; margin: 30px 0;">
                                    <p style="margin: 0 0 10px; color: #718096; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">
                                        Your Reset Code
                                    </p>
                                    <p style="margin: 0; color: #2d3748; font-size: 36px; font-weight: 700; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                                        {code}
                                    </p>
                                </div>
                                
                                <p style="margin: 0 0 20px; color: #2d3748; font-size: 16px; line-height: 1.6;">
                                    This code will expire in <strong>15 minutes</strong> for security reasons.
                                </p>
                                
                                <p style="margin: 0 0 20px; color: #718096; font-size: 14px; line-height: 1.6;">
                                    If you didn't request this password reset, please ignore this email or contact support if you have concerns.
                                </p>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="background-color: #f7fafc; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
                                <p style="margin: 0 0 10px; color: #718096; font-size: 14px;">
                                    <strong>NotesApp</strong> - Your personal workspace for productivity
                                </p>
                                <p style="margin: 0; color: #a0aec0; font-size: 12px;">
                                    This is an automated email, please do not reply.
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    return await send_email(email, subject, html_content)

async def send_share_notification_email(
    to_email: str,
    shared_by_name: str,
    item_type: str,  # "note" or "folder"
    item_title: str
) -> bool:
    """Send notification when a note or folder is shared"""
    subject = f"{shared_by_name} shared a {item_type} with you"
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:5173')
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Shared Content Notification</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f3f4f6; color: #1f2937;">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f3f4f6; padding: 40px 20px;">
            <tr>
                <td align="center">
                    <!-- Main Card -->
                    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width: 500px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);">
                        
                        <!-- Header with Icon -->
                        <tr>
                            <td style="padding: 40px 40px 20px 40px; text-align: center;">
                                <div style="display: inline-flex; align-items: center; justify-content: center; width: 64px; height: 64px; background-color: #e0e7ff; border-radius: 50%; margin-bottom: 20px;">
                                    <span style="font-size: 32px;">📤</span>
                                </div>
                                <h1 style="margin: 0; color: #111827; font-size: 24px; font-weight: 700; letter-spacing: -0.5px;">
                                    New {item_type.capitalize()} Shared
                                </h1>
                            </td>
                        </tr>
                        
                        <!-- Content -->
                        <tr>
                            <td style="padding: 0 40px 40px 40px; text-align: center;">
                                <p style="margin: 0 0 24px; color: #4b5563; font-size: 16px; line-height: 1.6;">
                                    <strong>{shared_by_name}</strong> has invited you to collaborate on a {item_type}.
                                </p>
                                
                                <!-- Item Preview -->
                                <div style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; margin-bottom: 32px; text-align: left;">
                                    <div style="font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; margin-bottom: 4px;">
                                        {item_type.upper()}
                                    </div>
                                    <div style="font-size: 18px; color: #111827; font-weight: 600; display: flex; align-items: center;">
                                        <span style="margin-right: 8px;">📄</span> {item_title}
                                    </div>
                                </div>
                                
                                <!-- Action Button -->
                                <a href="{frontend_url}" style="display: inline-block; background-color: #4f46e5; color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 16px; transition: background-color 0.2s;">
                                    Open {item_type.capitalize()}
                                </a>
                                
                                <p style="margin: 32px 0 0; color: #9ca3af; font-size: 14px;">
                                    Or copy this link to your browser:<br>
                                    <a href="{frontend_url}" style="color: #4f46e5; text-decoration: none; word-break: break-all;">{frontend_url}</a>
                                </p>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="background-color: #f9fafb; padding: 24px; text-align: center; border-top: 1px solid #e5e7eb;">
                                <p style="margin: 0; color: #9ca3af; font-size: 12px;">
                                    © 2024 NotesApp. All rights reserved.
                                </p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    return await send_email(to_email, subject, html_content)
