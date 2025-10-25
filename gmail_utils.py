# gmail_utils.py
# Gmail API helper functions (auth, fetch, label)

import os
import time
import base64
import pickle
from email import message_from_bytes
import re

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

from phishing_detector import Config, Console, EmailData


class GmailService:
    """Handles Gmail API interactions with proper error handling"""
    
    def __init__(self, config: Config):
        self.config = config
        self.service = self._authenticate()
        self.processed_label_id = self._get_or_create_label()
        self._label_cache = {}
    
    def _authenticate(self):
        """Authenticate with Gmail API with proper error handling"""
        creds = None
        
        if os.path.exists(self.config.TOKEN_FILE):
            try:
                with open(self.config.TOKEN_FILE, "rb") as f:
                    creds = pickle.load(f)
            except Exception as e:
                print(Console.yellow(f"Warning: Could not load token: {e}"))
                creds = None
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except RefreshError:
                    print(Console.yellow("Token refresh failed, re-authenticating..."))
                    os.remove(self.config.TOKEN_FILE)
                    creds = None
            
            if not creds:
                if not os.path.exists(self.config.CREDENTIALS_FILE):
                    raise FileNotFoundError(
                        f"credentials.json not found! Please download it from Google Cloud Console."
                    )
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.config.CREDENTIALS_FILE, 
                    self.config.SCOPES
                )
                creds = flow.run_local_server(port=0)
            
            with open(self.config.TOKEN_FILE, "wb") as f:
                pickle.dump(creds, f)
        
        return build("gmail", "v1", credentials=creds, cache_discovery=False)
    
    def _get_or_create_label(self) -> str:
        """Get or create the processed label"""
        try:
            labels_res = self.service.users().labels().list(userId="me").execute()
            
            for label in labels_res.get("labels", []):
                if label.get("name") == self.config.PROCESSED_LABEL:
                    return label["id"]
            
            label_body = {
                "name": self.config.PROCESSED_LABEL,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            }
            
            created = self.service.users().labels().create(
                userId="me", 
                body=label_body
            ).execute()
            
            return created["id"]
        except Exception as e:
            print(Console.red(f"Error creating label: {e}"))
            raise
    
    def get_label_id(self, label_name: str) -> str:
        """Get or create a label and return its ID (with caching)"""
        if label_name in self._label_cache:
            return self._label_cache[label_name]
        
        try:
            labels_res = self.service.users().labels().list(userId="me").execute()
            
            for label in labels_res.get("labels", []):
                if label.get("name") == label_name:
                    self._label_cache[label_name] = label["id"]
                    return label["id"]
            
            label_body = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            }
            
            created = self.service.users().labels().create(
                userId="me", 
                body=label_body
            ).execute()
            
            self._label_cache[label_name] = created["id"]
            return created["id"]
        except Exception as e:
            print(Console.yellow(f"Warning: Could not get/create label {label_name}: {e}"))
            return ""
    
    def fetch_latest_unread(self) -> Optional[str]:
        """Fetch the most recent unread email with retry logic"""
        for attempt in range(self.config.MAX_RETRIES):
            try:
                result = self.service.users().messages().list(
                    userId='me',
                    q="is:unread category:primary",
                    maxResults=5
                ).execute()
                
                messages = result.get('messages', [])
                if not messages:
                    return None
                
                msgs_with_date = []
                for msg in messages:
                    msg_detail = self.service.users().messages().get(
                        userId='me',
                        id=msg['id'],
                        format='metadata',
                        metadataHeaders=['Date']
                    ).execute()
                    msgs_with_date.append((msg['id'], int(msg_detail['internalDate'])))
                
                latest_msg_id = max(msgs_with_date, key=lambda x: x[1])[0]
                return latest_msg_id
            
            except Exception as e:
                if attempt < self.config.MAX_RETRIES - 1:
                    print(Console.yellow(f"Retry {attempt + 1}/{self.config.MAX_RETRIES}: {e}"))
                    time.sleep(self.config.RETRY_DELAY)
                else:
                    print(Console.red(f"Failed to fetch messages after {self.config.MAX_RETRIES} attempts: {e}"))
                    return None
        
        return None
    
    def parse_message(self, msg_id: str) -> EmailData:
        """Parse email message and extract content"""
        msg = self.service.users().messages().get(
            userId="me",
            id=msg_id,
            format="raw"
        ).execute()
        
        raw_bytes = base64.urlsafe_b64decode(msg["raw"].replace('-', '+').replace('_', '/'))
        email_msg = message_from_bytes(raw_bytes)
        
        subject = email_msg.get("Subject", "")
        sender = email_msg.get("From", "")
        body = self._extract_body(email_msg)
        snippet = body[:1000] if body else ""
        
        return EmailData(
            msg_id=msg_id,
            subject=subject,
            body=body,
            sender=sender,
            snippet=snippet
        )
    
    def _extract_body(self, email_msg) -> str:
        """Extract email body text"""
        body = ""
        
        if email_msg.is_multipart():
            for part in email_msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                
                if content_type == "text/plain" and "attachment" not in disposition:
                    try:
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
                    except:
                        body = str(part.get_payload())
                        break
            
            if not body:
                for part in email_msg.walk():
                    if part.get_content_type() == "text/html":
                        try:
                            body = part.get_payload(decode=True).decode(errors="ignore")
                            break
                        except:
                            body = str(part.get_payload())
                            break
        else:
            try:
                body = email_msg.get_payload(decode=True).decode(errors="ignore")
            except:
                body = str(email_msg.get_payload())
        
        return body
    
    def mark_as_processed(self, msg_id: str):
        """Mark message as processed"""
        try:
            body = {
                "removeLabelIds": ["UNREAD"],
                "addLabelIds": [self.processed_label_id]
            }
            self.service.users().messages().modify(
                userId="me",
                id=msg_id,
                body=body
            ).execute()
        except Exception as e:
            print(Console.yellow(f"Warning: Could not mark as processed: {e}"))
    
    def apply_label(self, msg_id: str, label_name: str):
        """Apply a specific label to a message"""
        try:
            label_id = self.get_label_id(label_name)
            if label_id:
                body = {"addLabelIds": [label_id]}
                self.service.users().messages().modify(
                    userId="me",
                    id=msg_id,
                    body=body
                ).execute()
        except Exception as e:
            print(Console.yellow(f"Warning: Could not apply label: {e}"))
    
    def move_to_spam(self, msg_id: str):
        """Move message to trash"""
        try:
            self.service.users().messages().trash(
                userId="me",
                id=msg_id
            ).execute()
        except Exception as e:
            print(Console.yellow(f"Warning: Could not move to trash: {e}"))
    
    def extract_sender_email(self, sender: str) -> str:
        """Extract email address from sender field"""
        match = re.search(r'<(.+?)>', sender)
        if match:
            return match.group(1).lower()
        return sender.lower()
