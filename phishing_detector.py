from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import openai
import base64
import os
import threading
import uuid
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configuration
OPENAI_API_KEY = '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'
CREDENTIALS_FILE = 'client_secret_903427469855-lfuog49uqdva54j2i02tujirj559jpro.apps.googleusercontent.com.json'
NUM_EMAILS = 5
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Global state
analysis_results = {}
task_status = {}

# Initialize OpenAI
openai.api_key = OPENAI_API_KEY

# Configure OAuth flow
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
flow = Flow.from_client_secrets_file(
    CREDENTIALS_FILE,
    scopes=SCOPES,
    redirect_uri='http://localhost:5000/callback'
)

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

def check_phishing(content):
    prompt = f"Analyze this email for phishing. Provide detailed analysis and conclude with either 'YES' (phishing) or 'NO' (legitimate):\n\n{content}"
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert analyzing emails for phishing attempts."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3
    )
    return response['choices'][0]['message']['content']

def analyze_emails(task_id, credentials_dict):
    try:
        creds = Credentials(
            token=credentials_dict['token'],
            refresh_token=credentials_dict['refresh_token'],
            token_uri=credentials_dict['token_uri'],
            client_id=credentials_dict['client_id'],
            client_secret=credentials_dict['client_secret'],
            scopes=credentials_dict['scopes']
        )
        
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', maxResults=NUM_EMAILS).execute()
        messages = results.get('messages', [])

        if not messages:
            analysis_results[task_id] = []
            task_status[task_id] = 'completed'
            return

        results_list = []
        for msg in messages:
            full_message = service.users().messages().get(userId='me', id=msg['id']).execute()
            subject = next(
                (header['value'] for header in full_message['payload']['headers'] 
                if header['name'] == 'Subject'), ""
            )
            
            content = extract_email_text(full_message)
            verdict = check_phishing(f"Subject: {subject}\n\nBody: {content}")
            
            is_phishing = "YES" in verdict.upper()
            results_list.append({
                'id': msg['id'],
                'subject': subject,
                'content_preview': content[:300] + '...' if len(content) > 300 else content,
                'verdict': verdict,
                'is_phishing': is_phishing,
                'received_at': full_message['internalDate']
            })
        
        analysis_results[task_id] = results_list
        task_status[task_id] = 'completed'
    except Exception as e:
        print(f"Analysis error: {str(e)}")
        analysis_results[task_id] = None
        task_status[task_id] = 'failed'

@app.route('/')
def index():
    if 'task_id' in session:
        task_id = session['task_id']
        if task_status.get(task_id) == 'completed':
            results = analysis_results.get(task_id, [])
            if results is not None:
                return render_template('dashboard.html', results=results)
            return render_template('error.html', message="Analysis failed - please try again")
        return render_template('analyzing.html')
    return render_template('phishing.html')

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    
    # Create a unique task ID
    task_id = str(uuid.uuid4())
    session['task_id'] = task_id
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    
    # Initialize task status
    task_status[task_id] = 'processing'
    
    # Start analysis in background
    thread = threading.Thread(
        target=analyze_emails,
        args=(task_id, session['credentials'])
    )
    thread.start()
    
    return redirect(url_for('phishing'))

@app.route('/status')
def status():
    task_id = session.get('task_id')
    if not task_id:
        return jsonify({'status': 'no_task'}), 404
    
    if task_id not in task_status:
        return jsonify({'status': 'not_found'}), 404
    
    return jsonify({
        'status': task_status[task_id],
        'results': analysis_results.get(task_id)
    })

@app.route('/logout')
def logout():
    task_id = session.get('task_id')
    if task_id in analysis_results:
        del analysis_results[task_id]
    if task_id in task_status:
        del task_status[task_id]
    session.clear()
    return redirect(url_for('phishing'))

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
