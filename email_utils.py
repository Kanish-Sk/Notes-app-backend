import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

load_dotenv()

# SMTP Configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USER)
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "NotesApp")

def send_email(to_email: str, subject: str, html_body: str, text_body: str = None):
    """
    Send an email via SMTP
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        html_body: HTML content of the email
        text_body: Plain text version (optional, will use html_body if not provided)
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        print("⚠️  SMTP credentials not configured. Email not sent.")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg['To'] = to_email
        
        # Add plain text version
        if text_body:
            part1 = MIMEText(text_body, 'plain')
            msg.attach(part1)
        
        # Add HTML version
        part2 = MIMEText(html_body, 'html')
        msg.attach(part2)
        
        # Connect to SMTP server and send
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        
        print(f"✅ Email sent successfully to {to_email}")
        return True
    
    except Exception as e:
        print(f"❌ Failed to send email to {to_email}: {str(e)}")
        return False


def send_password_reset_email(to_email: str, reset_code: str, user_name: str = None):
    """
    Send password reset email with 6-digit code
    
    Args:
        to_email: Recipient email address
        reset_code: 6-digit reset code
        user_name: Optional user name for personalization
    """
    greeting = f"Hi {user_name}," if user_name else "Hello,"
    
    subject = "Your Password Reset Code - NotesApp"
    
    # HTML version
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 40px 20px;">
            <tr>
                <td align="center">
                    <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); overflow: hidden;">
                        <!-- Header -->
                        <tr>
                            <td style="background: linear-gradient(135deg, #9333ea 0%, #3b82f6 100%); padding: 40px; text-align: center;">
                                <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 700;">📝 NotesApp</h1>
                            </td>
                        </tr>
                        
                        <!-- Content -->
                        <tr>
                            <td style="padding: 40px;">
                                <h2 style="color: #111827; font-size: 24px; margin: 0 0 16px 0; font-weight: 600;">Password Reset Request</h2>
                                
                                <p style="color: #4b5563; font-size: 16px; line-height: 24px; margin: 0 0 24px 0;">
                                    {greeting}
                                </p>
                                
                                <p style="color: #4b5563; font-size: 16px; line-height: 24px; margin: 0 0 24px 0;">
                                    We received a request to reset your password. Use the code below to complete the password reset process:
                                </p>
                                
                                <!-- Reset Code Box -->
                                <table width="100%" cellpadding="0" cellspacing="0" style="margin: 32px 0;">
                                    <tr>
                                        <td align="center" style="background-color: #f9fafb; border: 2px dashed #9333ea; border-radius: 12px; padding: 32px;">
                                            <p style="color: #6b7280; font-size: 14px; margin: 0 0 12px 0; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">Your Reset Code</p>
                                            <p style="color: #9333ea; font-size: 48px; font-weight: 700; margin: 0; font-family: 'Courier New', monospace; letter-spacing: 8px;">{reset_code}</p>
                                        </td>
                                    </tr>
                                </table>
                                
                                <div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; border-radius: 8px; margin: 24px 0;">
                                    <p style="color: #92400e; font-size: 14px; margin: 0; line-height: 20px;">
                                        <strong>⏱️ This code expires in 15 minutes</strong><br>
                                        If you didn't request this, please ignore this email.
                                    </p>
                                </div>
                                
                                <p style="color: #4b5563; font-size: 16px; line-height: 24px; margin: 24px 0 0 0;">
                                    For security reasons, this code will only work once. If you need a new code, please request another password reset.
                                </p>
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="background-color: #f9fafb; padding: 32px; text-align: center; border-top: 1px solid #e5e7eb;">
                                <p style="color: #6b7280; font-size: 14px; margin: 0 0 8px 0;">
                                    Need help? Contact us at support@notesapp.com
                                </p>
                                <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                                    © 2025 NotesApp. All rights reserved.
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
    
    # Plain text version
    text_body = f"""
Password Reset Request - NotesApp

{greeting}

We received a request to reset your password. Use the code below to complete the password reset process:

Your Reset Code: {reset_code}

⏱️ This code expires in 15 minutes.

If you didn't request this, please ignore this email.

For security reasons, this code will only work once. If you need a new code, please request another password reset.

---
Need help? Contact us at support@notesapp.com
© 2025 NotesApp. All rights reserved.
    """
    
    return send_email(to_email, subject, html_body, text_body)


def send_share_email(to_email: str, sender_name: str, note_title: str, is_new_user: bool = False):
    """
    Send email notification when a note is shared
    
    Args:
        to_email: Recipient email address
        sender_name: Name of the person sharing the note
        note_title: Title of the shared note
        is_new_user: Whether the recipient is a new user (not in DB)
    """
    subject = f"{sender_name} shared a note with you: {note_title}"
    
    action_text = "View Note" if not is_new_user else "Sign Up to View"
    action_url = "http://localhost:5173" # Base URL
    
    # HTML version
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 40px 20px;">
            <tr>
                <td align="center">
                    <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); overflow: hidden;">
                        <!-- Header -->
                        <tr>
                            <td style="background: linear-gradient(135deg, #9333ea 0%, #3b82f6 100%); padding: 40px; text-align: center;">
                                <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 700;">📝 NotesApp</h1>
                            </td>
                        </tr>
                        
                        <!-- Content -->
                        <tr>
                            <td style="padding: 40px;">
                                <h2 style="color: #111827; font-size: 24px; margin: 0 0 16px 0; font-weight: 600;">Note Shared With You</h2>
                                
                                <p style="color: #4b5563; font-size: 16px; line-height: 24px; margin: 0 0 24px 0;">
                                    <strong>{sender_name}</strong> has shared a note with you titled:
                                </p>
                                
                                <div style="background-color: #f9fafb; border-left: 4px solid #9333ea; padding: 20px; border-radius: 8px; margin: 0 0 32px 0;">
                                    <h3 style="color: #111827; font-size: 18px; margin: 0; font-weight: 600;">{note_title}</h3>
                                </div>
                                
                                <table width="100%" cellpadding="0" cellspacing="0">
                                    <tr>
                                        <td align="center">
                                            <a href="{action_url}" style="background-color: #9333ea; color: #ffffff; padding: 16px 32px; border-radius: 8px; text-decoration: none; font-weight: 600; display: inline-block; transition: background-color 0.2s;">
                                                {action_text}
                                            </a>
                                        </td>
                                    </tr>
                                </table>
                                
                                {f'''
                                <p style="color: #4b5563; font-size: 14px; line-height: 24px; margin: 32px 0 0 0; text-align: center;">
                                    Since you don't have an account yet, you'll need to sign up with this email address to view the note.
                                </p>
                                ''' if is_new_user else ''}
                            </td>
                        </tr>
                        
                        <!-- Footer -->
                        <tr>
                            <td style="background-color: #f9fafb; padding: 32px; text-align: center; border-top: 1px solid #e5e7eb;">
                                <p style="color: #6b7280; font-size: 14px; margin: 0 0 8px 0;">
                                    Need help? Contact us at support@notesapp.com
                                </p>
                                <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                                    © 2025 NotesApp. All rights reserved.
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
    
    # Plain text version
    text_body = f"""
Note Shared With You - NotesApp

{sender_name} has shared a note with you titled: "{note_title}"

To view this note, please visit: {action_url}

{'Note: You will need to sign up with this email address to view the note.' if is_new_user else ''}

---
Need help? Contact us at support@notesapp.com
© 2025 NotesApp. All rights reserved.
    """
    
    return send_email(to_email, subject, html_body, text_body)
