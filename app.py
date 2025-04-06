from flask import Flask, request, render_template, jsonify
import pandas as pd
import numpy as np
import joblib
import tempfile
import os
import statistics
from scapy.all import rdpcap

app = Flask(__name__)

knn_model = joblib.load("knn_model.pkl")
scaler = joblib.load("scaler.pkl")

TRAINING_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "SYN Flag Count",
    "URG Flag Count",
    "Avg Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init Fwd Win Bytes",
    "Init Bwd Win Bytes",
    "Fwd Act Data Packets",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    # Exclude "ClassLabel" from features
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

def extract_features_from_pcap(file_storage):
    """
    Reads the uploaded pcap file, assumes the pcap represents one flow,
    and computes many of the features required by the KNN model.
    
    The forward direction is defined as packets whose source IP equals the
    source IP of the first packet (if available). Many of the features (e.g.,
    active/idle durations, subflow metrics) are computed in a simplified way.
    
    Returns a DataFrame with one row of features.
    """
    # Save the uploaded pcap file to a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file_storage.read())
        tmp_path = tmp.name

    # Read packets using Scapy
    packets = rdpcap(tmp_path)
    os.remove(tmp_path)

    if len(packets) == 0:
        # No packets found; return zeros for all features.
        features = {col: 0 for col in TRAINING_COLUMNS}
        return pd.DataFrame([features])

    # Determine forward direction using the source IP of the first packet, if possible.
    first_pkt = packets[0]
    if "IP" in first_pkt:
        fwd_ip = first_pkt["IP"].src
    elif "IPv6" in first_pkt:
        fwd_ip = first_pkt["IPv6"].src
    else:
        fwd_ip = None

    # Initialize lists and counters for feature calculation.
    fwd_packets = []
    bwd_packets = []
    all_packet_lengths = []
    all_timestamps = []

    # Variables for TCP flag counts and header lengths (only computed if TCP layer is present).
    fwd_psh_count = 0
    fwd_syn_count = 0
    fwd_urg_count = 0
    fwd_header_lengths = []
    bwd_header_lengths = []
    fwd_payload_sizes = []
    bwd_payload_sizes = []
    total_bytes = 0

    # For initial TCP window sizes, store the first observed window from each direction.
    init_fwd_win = None
    init_bwd_win = None

    # Variables for active/idle period computation.
    active_durations = []
    idle_durations = []
    threshold = 1.0  # seconds to separate active from idle
    prev_time = None

    # Process each packet.
    for pkt in packets:
        pkt_time = pkt.time
        all_timestamps.append(pkt_time)
        pkt_len = len(pkt)
        all_packet_lengths.append(pkt_len)
        total_bytes += pkt_len

        # Determine packet direction.
        if fwd_ip and "IP" in pkt:
            direction = "fwd" if pkt["IP"].src == fwd_ip else "bwd"
        else:
            direction = "fwd"

        # Compute inter-arrival times for active/idle calculation.
        if prev_time is not None:
            diff = pkt_time - prev_time
            if diff <= threshold:
                active_durations.append(diff)
            else:
                idle_durations.append(diff)
        prev_time = pkt_time

        # Process TCP layer if available.
        tcp_layer = pkt.getlayer("TCP")
        ip_layer = pkt.getlayer("IP")
        if tcp_layer:
            flags = str(tcp_layer.flags)
            # For forward packets, update flag counts.
            if direction == "fwd":
                if 'P' in flags:
                    fwd_psh_count += 1
                if 'S' in flags:
                    fwd_syn_count += 1
                if 'U' in flags:
                    fwd_urg_count += 1
            # Calculate header length.
            # If available, tcp_layer.dataofs gives header length in 32-bit words.
            tcp_header_len = tcp_layer.dataofs * 4 if hasattr(tcp_layer, 'dataofs') and tcp_layer.dataofs else 20
            # Assume a standard IPv4 header length of 20 bytes if present.
            ip_header_len = 20 if ip_layer else 0
            header_len = tcp_header_len + ip_header_len
            if direction == "fwd":
                fwd_header_lengths.append(header_len)
            else:
                bwd_header_lengths.append(header_len)
            # Calculate payload size (packet length minus header length).
            payload_size = pkt_len - header_len if pkt_len > header_len else 0
            if direction == "fwd":
                fwd_payload_sizes.append(payload_size)
            else:
                bwd_payload_sizes.append(payload_size)
            # Store initial TCP window size if not already set.
            if direction == "fwd" and init_fwd_win is None:
                init_fwd_win = tcp_layer.window
            if direction == "bwd" and init_bwd_win is None:
                init_bwd_win = tcp_layer.window

        # Append packet to the corresponding list.
        if direction == "fwd":
            fwd_packets.append(pkt)
        else:
            bwd_packets.append(pkt)

    # Compute flow duration.
    flow_duration = max(all_timestamps) - min(all_timestamps)
    if flow_duration <= 0:
        flow_duration = 0.001  # prevent division by zero

    # Total forward and backward packet counts.
    total_fwd_packets = len(fwd_packets)
    total_bwd_packets = len(bwd_packets)

    # Compute total bytes for forward and backward directions.
    fwd_packets_length_total = sum(len(pkt) for pkt in fwd_packets)
    bwd_packets_length_total = sum(len(pkt) for pkt in bwd_packets)

    # Compute forward packet length statistics.
    if fwd_packets:
        fwd_lengths = [len(pkt) for pkt in fwd_packets]
        fwd_max = max(fwd_lengths)
        fwd_mean = statistics.mean(fwd_lengths)
        fwd_std = statistics.stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0
    else:
        fwd_max = fwd_mean = fwd_std = 0

    # Compute backward packet length statistics.
    if bwd_packets:
        bwd_lengths = [len(pkt) for pkt in bwd_packets]
        bwd_max = max(bwd_lengths)
        bwd_mean = statistics.mean(bwd_lengths)
        bwd_std = statistics.stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0
    else:
        bwd_max = bwd_mean = bwd_std = 0

    # Compute overall flow metrics.
    total_bytes_flow = sum(all_packet_lengths)
    flow_bytes_per_sec = total_bytes_flow / flow_duration
    flow_packets_per_sec = len(all_packet_lengths) / flow_duration

    # Inter-arrival times (IAT) for all packets.
    all_iats = [t2 - t1 for t1, t2 in zip(all_timestamps, all_timestamps[1:])]
    flow_iat_mean = statistics.mean(all_iats) if all_iats else 0
    flow_iat_std = statistics.stdev(all_iats) if len(all_iats) > 1 else 0
    flow_iat_max = max(all_iats) if all_iats else 0
    flow_iat_min = min(all_iats) if all_iats else 0

    # IAT metrics for forward packets.
    fwd_times = [pkt.time for pkt in fwd_packets]
    fwd_iats = [t2 - t1 for t1, t2 in zip(fwd_times, fwd_times[1:])]
    fwd_iat_total = sum(fwd_iats) if fwd_iats else 0
    fwd_iat_mean = statistics.mean(fwd_iats) if fwd_iats else 0
    fwd_iat_std = statistics.stdev(fwd_iats) if len(fwd_iats) > 1 else 0
    fwd_iat_max = max(fwd_iats) if fwd_iats else 0
    fwd_iat_min = min(fwd_iats) if fwd_iats else 0

    # IAT metrics for backward packets.
    bwd_times = [pkt.time for pkt in bwd_packets]
    bwd_iats = [t2 - t1 for t1, t2 in zip(bwd_times, bwd_times[1:])]
    bwd_iat_total = sum(bwd_iats) if bwd_iats else 0
    bwd_iat_mean = statistics.mean(bwd_iats) if bwd_iats else 0
    bwd_iat_std = statistics.stdev(bwd_iats) if len(bwd_iats) > 1 else 0
    bwd_iat_max = max(bwd_iats) if bwd_iats else 0
    bwd_iat_min = min(bwd_iats) if bwd_iats else 0

    # Compute packets per second for forward and backward directions.
    fwd_packets_per_sec = total_fwd_packets / flow_duration
    bwd_packets_per_sec = total_bwd_packets / flow_duration

    # Overall packet length statistics.
    packet_length_max = max(all_packet_lengths) if all_packet_lengths else 0
    packet_length_mean = statistics.mean(all_packet_lengths) if all_packet_lengths else 0
    packet_length_std = statistics.stdev(all_packet_lengths) if len(all_packet_lengths) > 1 else 0
    packet_length_variance = statistics.variance(all_packet_lengths) if len(all_packet_lengths) > 1 else 0

    # SYN and URG flag counts (using forward packets).
    syn_flag_count = fwd_syn_count
    urg_flag_count = fwd_urg_count

    # Average packet size.
    avg_packet_size = total_bytes_flow / len(all_packet_lengths) if all_packet_lengths else 0

    # Average segment sizes (payload sizes) for forward and backward packets.
    avg_fwd_segment_size = statistics.mean(fwd_payload_sizes) if fwd_payload_sizes else 0
    avg_bwd_segment_size = statistics.mean(bwd_payload_sizes) if bwd_payload_sizes else 0

    # For subflow metrics and active/idle periods, we use simplified/dummy values.
    subflow_fwd_packets = 0
    subflow_fwd_bytes = 0
    subflow_bwd_packets = 0
    subflow_bwd_bytes = 0

    # Initial window sizes (default to 0 if not found).
    init_fwd_win_bytes = init_fwd_win if init_fwd_win is not None else 0
    init_bwd_win_bytes = init_bwd_win if init_bwd_win is not None else 0

    # Forward active data packets: count of forward packets with nonzero payload.
    fwd_act_data_packets = sum(1 for size in fwd_payload_sizes if size > 0)
    # Minimum segment size among forward packets.
    fwd_seg_size_min = min(fwd_payload_sizes) if fwd_payload_sizes else 0

    # Active/Idle period statistics.
    active_mean = statistics.mean(active_durations) if active_durations else 0
    active_std = statistics.stdev(active_durations) if len(active_durations) > 1 else 0
    active_max = max(active_durations) if active_durations else 0
    active_min = min(active_durations) if active_durations else 0

    idle_mean = statistics.mean(idle_durations) if idle_durations else 0
    idle_std = statistics.stdev(idle_durations) if len(idle_durations) > 1 else 0
    idle_max = max(idle_durations) if idle_durations else 0
    idle_min = min(idle_durations) if idle_durations else 0

    features = {
        "Flow Duration": flow_duration,
        "Total Fwd Packets": total_fwd_packets,
        "Total Backward Packets": total_bwd_packets,
        "Fwd Packets Length Total": fwd_packets_length_total,
        "Bwd Packets Length Total": bwd_packets_length_total,
        "Fwd Packet Length Max": fwd_max,
        "Fwd Packet Length Mean": fwd_mean,
        "Fwd Packet Length Std": fwd_std,
        "Bwd Packet Length Max": bwd_max,
        "Bwd Packet Length Mean": bwd_mean,
        "Bwd Packet Length Std": bwd_std,
        "Flow Bytes/s": flow_bytes_per_sec,
        "Flow Packets/s": flow_packets_per_sec,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,
        "Fwd IAT Total": fwd_iat_total,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": fwd_psh_count,
        "Fwd Header Length": statistics.mean(fwd_header_lengths) if fwd_header_lengths else 0,
        "Bwd Header Length": statistics.mean(bwd_header_lengths) if bwd_header_lengths else 0,
        "Fwd Packets/s": fwd_packets_per_sec,
        "Bwd Packets/s": bwd_packets_per_sec,
        "Packet Length Max": packet_length_max,
        "Packet Length Mean": packet_length_mean,
        "Packet Length Std": packet_length_std,
        "Packet Length Variance": packet_length_variance,
        "SYN Flag Count": syn_flag_count,
        "URG Flag Count": urg_flag_count,
        "Avg Packet Size": avg_packet_size,
        "Avg Fwd Segment Size": avg_fwd_segment_size,
        "Avg Bwd Segment Size": avg_bwd_segment_size,
        "Subflow Fwd Packets": subflow_fwd_packets,
        "Subflow Fwd Bytes": subflow_fwd_bytes,
        "Subflow Bwd Packets": subflow_bwd_packets,
        "Subflow Bwd Bytes": subflow_bwd_bytes,
        "Init Fwd Win Bytes": init_fwd_win_bytes,
        "Init Bwd Win Bytes": init_bwd_win_bytes,
        "Fwd Act Data Packets": fwd_act_data_packets,
        "Fwd Seg Size Min": fwd_seg_size_min,
        "Active Mean": active_mean,
        "Active Std": active_std,
        "Active Max": active_max,
        "Active Min": active_min,
        "Idle Mean": idle_mean,
        "Idle Std": idle_std,
        "Idle Max": idle_max,
        "Idle Min": idle_min
    }

    return pd.DataFrame([features])

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
    
    # Process based on file type.
    if file_ext == ".pcap":
        df = extract_features_from_pcap(file)
    elif file_ext == ".csv":
        df = pd.read_csv(file)
    elif file_ext == ".json":
        df = pd.read_json(file)
    else:
        return jsonify({"error": "Unsupported file type. Only pcap, csv, or json files are supported."}), 400

    # Ensure the DataFrame has the required columns.
    try:
        X = df[TRAINING_COLUMNS]
    except KeyError as e:
        return jsonify({"error": f"Uploaded file does not have the required columns: {str(e)}"}), 400

    # Scale the features using the pre-loaded scaler.
    X_scaled = scaler.transform(X)

    # Predict with the KNN model.
    predictions = knn_model.predict(X_scaled)

    # Count predictions mapped to our front-end categories.
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
        category = label_to_category(label)
        if category in threat_counts:
            threat_counts[category] += 1

    return jsonify(threat_counts)

@app.route('/homepage')
def homepage():
    return render_template('homepage.html')

if __name__ == '__main__':
    app.run(debug=True)
