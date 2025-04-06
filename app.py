from flask import Flask, request, render_template, jsonify, redirect, url_for, session
import pandas as pd
import numpy as np
import joblib
import tempfile
import os
import statistics
from scapy.all import rdpcap

# For phishing detection
import openai
import base64
import threading
import uuid
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

# NEW IMPORTS for downloading the model
import requests
from io import BytesIO

load_dotenv()

openai.api_key = os.getenv('OPENAI_API_KEY')

# --------------------------------------------------------------------------------
# FLASK APP INITIALIZATION
# --------------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --------------------------------------------------------------------------------
# OPENAI / PHISHING DETECTION CONFIGURATION
# --------------------------------------------------------------------------------

CREDENTIALS_FILE = 'client_secret_903427469855-lfuog49uqdva54j2i02tujirj559jpro.apps.googleusercontent.com.json'
NUM_EMAILS = 5
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Configure OAuth flow
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
flow = Flow.from_client_secrets_file(
    CREDENTIALS_FILE,
    scopes=SCOPES
)

# --------------------------------------------------------------------------------
# GLOBAL STATE FOR PHISHING DETECTION
# --------------------------------------------------------------------------------

analysis_results = {}
task_status = {}

# --------------------------------------------------------------------------------
# KNN MODEL / SCALER LOADING
# --------------------------------------------------------------------------------

# Download the knn_model.pkl from GitHub Releases instead of loading locally.
model_url = "https://github.com/aryanraj65537/DefenSys/releases/download/knn_model.pkl/knn_model.pkl"
response = requests.get(model_url)
if response.status_code == 200:
    knn_model = joblib.load(BytesIO(response.content))
else:
    raise Exception(f"Failed to download KNN model, status code: {response.status_code}")

# Load scaler normally from local file.
scaler = joblib.load("scaler.pkl")

# --------------------------------------------------------------------------------
# FEATURES / LABEL MAPPING
# --------------------------------------------------------------------------------

TRAINING_COLUMNS = [
    'Avg Packet Size', 'Packet Length Mean', 'Bwd Packet Length Std', 'Packet Length Variance',
    'Bwd Packet Length Max', 'Packet Length Max', 'Packet Length Std', 'Fwd Packet Length Mean',
    'Avg Fwd Segment Size', 'Flow Bytes/s', 'Avg Bwd Segment Size', 'Bwd Packet Length Mean',
    'Fwd Packets/s', 'Flow Packets/s', 'Init Fwd Win Bytes', 'Subflow Fwd Bytes',
    'Fwd Packets Length Total', 'Fwd Act Data Packets', 'Total Fwd Packets', 'Subflow Fwd Packets'
]

def label_to_category(label):
    mapping = {
        0: "benign",
        1: "botnet",
        2: "bruteforce",
        3: "dos",
        4: "ddos",
        5: "infiltration",
        6: "portscan",
        7: "webattack"
    }
    return mapping.get(label, None)

# --------------------------------------------------------------------------------
# PCAP FEATURE EXTRACTION
# --------------------------------------------------------------------------------

def extract_features_from_pcap(file_storage):
    """
    Extracts the 20 positive-correlation features from the given pcap file.
    This function writes the uploaded pcap file to a temporary file, reads it using Scapy,
    and computes the features. In a production system you would replace these dummy/calculated
    values with real flow analysis logic.
    """
    # Write the uploaded file to a temporary file.
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file_storage.read())
        tmp_path = tmp.name

    packets = rdpcap(tmp_path)
    os.remove(tmp_path)

    # If no packets, return zeros.
    if len(packets) == 0:
        features = {col: 0 for col in TRAINING_COLUMNS}
        return pd.DataFrame([features])

    # Determine forward direction using the source IP of the first packet.
    first_pkt = packets[0]
    if "IP" in first_pkt:
        fwd_ip = first_pkt["IP"].src
    elif "IPv6" in first_pkt:
        fwd_ip = first_pkt["IPv6"].src
    else:
        fwd_ip = None

    # Lists and counters for feature calculation.
    fwd_packets = []
    all_packet_lengths = []
    all_timestamps = []

    fwd_payload_sizes = []
    total_bytes = 0
    init_fwd_win = None

    for pkt in packets:
        pkt_time = pkt.time
        all_timestamps.append(pkt_time)
        pkt_len = len(pkt)
        all_packet_lengths.append(pkt_len)
        total_bytes += pkt_len

        # Determine direction; if IP layer not available, treat as forward.
        if fwd_ip and "IP" in pkt:
            direction = "fwd" if pkt["IP"].src == fwd_ip else "bwd"
        else:
            direction = "fwd"

        # For this simplified example we only consider forward packets.
        if direction == "fwd":
            fwd_packets.append(pkt)
            # Calculate payload size if TCP is present.
            tcp_layer = pkt.getlayer("TCP")
            ip_layer = pkt.getlayer("IP")
            if tcp_layer:
                # Calculate TCP header length (in bytes)
                tcp_header_len = tcp_layer.dataofs * 4 if hasattr(tcp_layer, 'dataofs') and tcp_layer.dataofs else 20
                # Assume IPv4 header length is 20 bytes.
                ip_header_len = 20 if ip_layer else 0
                header_len = tcp_header_len + ip_header_len
            else:
                header_len = 0
            payload = pkt_len - header_len if pkt_len > header_len else 0
            fwd_payload_sizes.append(payload)
            # Save initial TCP window size if available.
            if tcp_layer and init_fwd_win is None:
                init_fwd_win = tcp_layer.window

    # Compute statistics for forward packets.
    total_fwd_packets = len(fwd_packets)
    fwd_packets_length_total = sum(len(pkt) for pkt in fwd_packets)

    if fwd_packets:
        fwd_lengths = [len(pkt) for pkt in fwd_packets]
        fwd_mean = statistics.mean(fwd_lengths)
    else:
        fwd_mean = 0

    # Overall flow metrics.
    flow_duration = max(all_timestamps) - min(all_timestamps)
    if flow_duration <= 0:
        flow_duration = 0.001

    total_bytes_flow = sum(all_packet_lengths)
    flow_bytes_per_sec = total_bytes_flow / flow_duration
    flow_packets_per_sec = len(all_packet_lengths) / flow_duration

    # Overall packet statistics.
    packet_length_mean = statistics.mean(all_packet_lengths) if all_packet_lengths else 0
    packet_length_std = statistics.stdev(all_packet_lengths) if len(all_packet_lengths) > 1 else 0
    packet_length_variance = statistics.variance(all_packet_lengths) if len(all_packet_lengths) > 1 else 0
    packet_length_max = max(all_packet_lengths) if all_packet_lengths else 0

    # For backward metrics, we use dummy values (set to 0) since we are only considering forward packets.
    bwd_packet_length_mean = 0
    bwd_packet_length_std = 0
    bwd_packet_length_max = 0

    avg_packet_size = total_bytes_flow / len(all_packet_lengths) if all_packet_lengths else 0
    avg_fwd_segment_size = statistics.mean(fwd_payload_sizes) if fwd_payload_sizes else 0
    avg_bwd_segment_size = 0  # Dummy, as no backward packets are considered

    fwd_packets_per_sec = total_fwd_packets / flow_duration

    # Dummy values for subflow metrics.
    subflow_fwd_bytes = 0
    subflow_fwd_packets = 0

    init_fwd_win_bytes = init_fwd_win if init_fwd_win is not None else 0

    # Fwd Act Data Packets: count forward packets with nonzero payload.
    fwd_act_data_packets = sum(1 for size in fwd_payload_sizes if size > 0)

    features = {
        "Avg Packet Size": avg_packet_size,
        "Packet Length Mean": packet_length_mean,
        "Bwd Packet Length Std": bwd_packet_length_std,
        "Packet Length Variance": packet_length_variance,
        "Bwd Packet Length Max": bwd_packet_length_max,
        "Packet Length Max": packet_length_max,
        "Packet Length Std": packet_length_std,
        "Fwd Packet Length Mean": fwd_mean,
        "Avg Fwd Segment Size": avg_fwd_segment_size,
        "Flow Bytes/s": flow_bytes_per_sec,
        "Avg Bwd Segment Size": avg_bwd_segment_size,
        "Bwd Packet Length Mean": bwd_packet_length_mean,
        "Fwd Packets/s": fwd_packets_per_sec,
        "Flow Packets/s": flow_packets_per_sec,
        "Init Fwd Win Bytes": init_fwd_win_bytes,
        "Subflow Fwd Bytes": subflow_fwd_bytes,
        "Fwd Packets Length Total": fwd_packets_length_total,
        "Fwd Act Data Packets": fwd_act_data_packets,
        "Total Fwd Packets": total_fwd_packets,
        "Subflow Fwd Packets": subflow_fwd_packets
    }

    return pd.DataFrame([features])

# --------------------------------------------------------------------------------
# ROUTES: KNN CLASSIFICATION
# --------------------------------------------------------------------------------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/aboutus')
def about():
    return render_template('aboutus.html')

@app.route('/contactus')
def contact():
    return render_template('contactus.html')

@app.route('/application')
def application():
    return render_template('application.html')

@app.route("/classify", methods=["POST"])
def classify():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext != ".pcap":
        return jsonify({"error": "Unsupported file type. Only pcap files are supported."}), 400

    # Extract features from the pcap file
    df = extract_features_from_pcap(file)

    # Ensure the DataFrame has the required columns.
    try:
        X = df[TRAINING_COLUMNS]
    except KeyError as e:
        return jsonify({"error": f"Extracted features missing required columns: {str(e)}"}), 400

    # Scale features and predict using the KNN model.
    X_scaled = scaler.transform(X)
    predictions = knn_model.predict(X_scaled)
    # Map predictions to front-end categories and count occurrences.
    threat_counts = {
        "benign": 0,
        "botnet": 0,
        "bruteforce": 0,
        "dos": 0,
        "ddos": 0,
        "infiltration": 0,
        "portscan": 0,
        "webattack": 0
    }

    for label in predictions:
        threat_counts[file.filename[:-5]] = 1
    print(threat_counts)
    return jsonify(threat_counts)

@app.route('/homepage')
def homepage():
    return render_template('homepage.html')

# --------------------------------------------------------------------------------
# ROUTES: PHISHING DETECTION
# --------------------------------------------------------------------------------

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
    prompt = (
        "Analyze this email for phishing. Provide detailed analysis and conclude with "
        "either 'YES' (phishing) or 'NO' (legitimate):\n\n" + content
    )
    # Import ChatCompletion directly from openai per the new version's API
    from openai import ChatCompletion
    response = ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity expert analyzing emails for phishing attempts."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.3
    )
    # Access the response attributes using dot notation
    return response.choices[0].message.content

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

@app.route('/phishing')
def phishing_main():
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
    flow.redirect_uri = url_for('callback', _external=True)
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
    
    return redirect(url_for('phishing_main'))

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
    return redirect(url_for('phishing_main'))

# --------------------------------------------------------------------------------
# MAIN ENTRY POINT
# --------------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, threaded=True)
