import openai
import base64
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# === CONFIG ===
OPENAI_API_KEY = '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'
CREDENTIALS_FILE = 'client_secret_903427469855-lfuog49uqdva54j2i02tujirj559jpro.apps.googleusercontent.com.json'
NUM_EMAILS = 5
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# === SETUP OPENAI ===
openai.api_key = OPENAI_API_KEY

# === AUTHENTICATE GMAIL ===
def authenticate_gmail():
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
    creds = flow.run_local_server(port=0)
    return build('gmail', 'v1', credentials=creds)

# === EXTRACT EMAIL TEXT ===
def extract_email_text(message):
    try:
        parts = message['payload']['parts']
        for part in parts:
            if part['mimeType'] == 'text/plain':
                data = part['body']['data']
                text = base64.urlsafe_b64decode(data).decode('utf-8')
                return text
    except Exception:
        pass
    return message.get('snippet', '')

# === CHECK FOR PHISHING ===
def check_phishing(content):
    prompt = f"Is this email phishing? Be detailed and return YES or NO at the end.\n\nEmail:\n{content}"
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a phishing detection assistant."},
            {"role": "user", "content": prompt}
        ]
    )
    return response['choices'][0]['message']['content']

# === MAIN PROGRAM ===
def main():
    service = authenticate_gmail()
    results = service.users().messages().list(userId='me', maxResults=NUM_EMAILS).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No messages found.")
        return

    for idx, msg in enumerate(messages, 1):
        full_message = service.users().messages().get(userId='me', id=msg['id']).execute()
        subject = ""
        for header in full_message['payload']['headers']:
            if header['name'] == 'Subject':
                subject = header['value']
                break

        content = extract_email_text(full_message)
        print(f"\n=== EMAIL #{idx} ===")
        print(f"Subject: {subject}")
        print(f"Content Preview: {content[:300]}...")

        verdict = check_phishing(f"Subject: {subject}\n\nBody: {content}")
        print(f"\n🔍 Verdict from AI:\n{verdict}")
        print("="*60)

if __name__ == '__main__':
    main()
