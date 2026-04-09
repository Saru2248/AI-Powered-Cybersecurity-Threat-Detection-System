"""
=============================================================
  AI-Powered Cybersecurity Threat Detection System
  Module: threat_detector.py
  Purpose: Run the real-time (simulated) threat detection
           pipeline. Takes network events, runs predictions,
           classifies threat type, and generates alerts.
=============================================================
"""

import os
import time
import numpy as np
import pandas as pd
import joblib
from colorama import Fore, Back, Style, init
from datetime import datetime

init(autoreset=True)

# ─────────────────────────────────────────────────────────
# SECTION 1: Threat Classification Logic
# ─────────────────────────────────────────────────────────

# Feature list must match training (from preprocessor.py)
FEATURE_COLUMNS = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'count', 'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
    'bytes_ratio', 'total_bytes', 'error_ratio', 'service_similarity',
    'bytes_per_second', 'login_risk', 'conn_density'
]

# Threat threat severity levels
SEVERITY_MAP = {
    'normal':           ('INFO',     Fore.GREEN),
    'dos':              ('CRITICAL', Fore.RED),
    'probe':            ('MEDIUM',   Fore.YELLOW),
    'brute_force':      ('HIGH',     Fore.MAGENTA),
    'r2l_exfiltration': ('HIGH',     Fore.MAGENTA),
    'unknown_anomaly':  ('HIGH',     Fore.RED),
}


def classify_threat_type(row):
    """
    Rule-based heuristic threat classifier.
    Uses feature thresholds to identify attack category.
    In a real SOC system, this would use the multi-class
    model prediction, but thresholds add interpretability.

    Parameters:
        row (pd.Series): A single network traffic record

    Returns:
        str: Detected threat type label
    """
    # DoS: high connection count + high error rate + no login
    if row['count'] > 200 and row['serror_rate'] > 0.7 and row['logged_in'] == 0:
        return 'dos'

    # Brute Force: many failed logins
    if row['num_failed_logins'] >= 3:
        return 'brute_force'

    # Data Exfiltration / R2L: very large outbound bytes
    if row['dst_bytes'] > 6000 and row['num_compromised'] > 1:
        return 'r2l_exfiltration'

    # Probe / Port Scan: high diff_srv_rate + low bytes
    if row['diff_srv_rate'] > 0.6 and row['total_bytes'] < 500:
        return 'probe'

    return 'unknown_anomaly'


# ─────────────────────────────────────────────────────────
# SECTION 2: Load Models and Scaler
# ─────────────────────────────────────────────────────────

def load_detector_components(model_path="models/best_model.pkl",
                             scaler_path="models/scaler.pkl",
                             iso_path="models/isolation_forest.pkl"):
    """
    Load all saved model components from disk.

    Returns:
        tuple: (model, scaler, iso_forest)
    """
    print(Fore.CYAN + "\n[DETECTOR] Loading model components...")

    model, scaler, iso = None, None, None

    if os.path.exists(model_path):
        model = joblib.load(model_path)
        print(Fore.GREEN + f"  ✓ Classifier loaded   → {model_path}")
    else:
        print(Fore.RED + f"  ✗ Classifier missing  → {model_path}")

    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
        print(Fore.GREEN + f"  ✓ Scaler loaded       → {scaler_path}")
    else:
        print(Fore.RED + f"  ✗ Scaler missing      → {scaler_path}")

    if os.path.exists(iso_path):
        iso = joblib.load(iso_path)
        print(Fore.GREEN + f"  ✓ Anomaly detector loaded → {iso_path}")
    else:
        print(Fore.YELLOW + f"  ! Anomaly detector not found → {iso_path}")

    return model, scaler, iso


# ─────────────────────────────────────────────────────────
# SECTION 3: Single Event Detection
# ─────────────────────────────────────────────────────────

def detect_single_event(event_dict, model, scaler, iso=None):
    """
    Run threat detection on a single network event.

    Parameters:
        event_dict (dict): Feature values for one connection
        model: Trained classifier
        scaler: Fitted StandardScaler
        iso: Optional Isolation Forest

    Returns:
        dict: Detection result with label, type,
              severity, confidence, timestamp
    """
    # Convert dict to DataFrame for processing
    event_df = pd.DataFrame([event_dict])

    # Add engineered features (same as training)
    event_df['bytes_ratio']        = event_df['dst_bytes'] / (event_df['src_bytes'] + 1)
    event_df['total_bytes']        = event_df['src_bytes'] + event_df['dst_bytes']
    event_df['error_ratio']        = (event_df['serror_rate'] + event_df['rerror_rate']) / 2
    event_df['service_similarity'] = event_df['same_srv_rate'] - event_df['diff_srv_rate']
    event_df['bytes_per_second']   = event_df['total_bytes'] / (event_df['duration'] + 0.001)
    event_df['login_risk']         = event_df['num_failed_logins'] * 2 + event_df['num_compromised']
    event_df['conn_density']       = event_df['count'] / (event_df['dst_host_count'] + 1)

    # Scale features
    X = scaler.transform(event_df[FEATURE_COLUMNS].values)

    # Predict with classifier
    prediction = model.predict(X)[0]
    proba = model.predict_proba(X)[0] if hasattr(model, 'predict_proba') else [0.5, 0.5]
    confidence = max(proba) * 100

    # Anomaly score from Isolation Forest
    anomaly_score = None
    iso_pred = None
    if iso is not None:
        raw = iso.predict(X)
        iso_pred = int(raw[0] == -1)     # 1 if anomaly
        anomaly_score = round(-iso.decision_function(X)[0], 4)

    # Determine threat type
    if prediction == 1:
        threat_type = classify_threat_type(event_df.iloc[0])
    else:
        threat_type = 'normal'

    result = {
        'timestamp':     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'label':         int(prediction),
        'threat_type':   threat_type,
        'confidence':    round(confidence, 2),
        'anomaly_score': anomaly_score,
        'iso_flag':      iso_pred,
        'is_threat':     bool(prediction == 1)
    }

    return result


# ─────────────────────────────────────────────────────────
# SECTION 4: Alert Printer
# ─────────────────────────────────────────────────────────

def print_alert(result, event_idx=None):
    """
    Print a formatted threat alert to the console.
    Color-coded by severity level.
    """
    severity, color = SEVERITY_MAP.get(result['threat_type'], ('UNKNOWN', Fore.WHITE))
    prefix = f"[Event #{event_idx}] " if event_idx is not None else ""

    if result['is_threat']:
        print(color + Back.BLACK +
              f"\n{'='*58}")
        print(color + f"  🚨 {prefix}THREAT DETECTED!")
        print(color + f"  Type       : {result['threat_type'].upper()}")
        print(color + f"  Severity   : {severity}")
        print(color + f"  Confidence : {result['confidence']:.1f}%")
        if result['anomaly_score'] is not None:
            print(color + f"  Anom Score : {result['anomaly_score']:.4f}")
        print(color + f"  Timestamp  : {result['timestamp']}")
        print(color + f"{'='*58}")
    else:
        print(Fore.GREEN +
              f"  ✓ {prefix}Normal Traffic "
              f"(conf={result['confidence']:.1f}%,  "
              f"time={result['timestamp']})")


# ─────────────────────────────────────────────────────────
# SECTION 5: Batch Detection Pipeline
# ─────────────────────────────────────────────────────────

def run_batch_detection(df, model, scaler, iso=None,
                        simulate_realtime=False,
                        save_results_path=None):
    """
    Run detection on a batch of network events.
    Optionally simulates real-time by adding small delays.

    Parameters:
        df (pd.DataFrame): Data with feature columns
        model: Trained classifier
        scaler: Fitted scaler
        iso: Optional Isolation Forest
        simulate_realtime (bool): Add delays between events
        save_results_path (str): Save results CSV path

    Returns:
        pd.DataFrame: Results table
    """
    print(Fore.CYAN + "\n" + "="*58)
    print(Fore.CYAN + "  REAL-TIME THREAT DETECTION SIMULATION")
    print(Fore.CYAN + "="*58)

    results_list = []
    threat_count = 0
    threat_types = {}

    for idx, (_, row) in enumerate(df.iterrows()):
        event = row.to_dict()

        # Remove non-feature columns if present
        for col in ['label', 'attack_type', 'bytes_ratio', 'total_bytes',
                    'error_ratio', 'service_similarity', 'bytes_per_second',
                    'login_risk', 'conn_density']:
            event.pop(col, None)

        result = detect_single_event(event, model, scaler, iso)
        result['event_id'] = idx

        # Copy original label for later comparison
        if 'label' in row:
            result['true_label'] = int(row['label'])
        if 'attack_type' in row:
            result['true_attack_type'] = row['attack_type']

        results_list.append(result)

        # Print every event
        print_alert(result, event_idx=idx)

        if result['is_threat']:
            threat_count += 1
            t = result['threat_type']
            threat_types[t] = threat_types.get(t, 0) + 1

        if simulate_realtime:
            time.sleep(0.15)  # 150ms delay between events

    # ── Summary ─────────────────────────────────────────
    total = len(results_list)
    print(Fore.CYAN + "\n" + "="*58)
    print(Fore.CYAN + "  DETECTION SUMMARY")
    print(Fore.CYAN + "="*58)
    print(f"  Total Events Analyzed : {total}")
    print(Fore.RED + f"  Threats Detected      : {threat_count}")
    print(Fore.GREEN + f"  Normal Events         : {total - threat_count}")
    print(f"\n  Threat Breakdown:")
    for ttype, count in sorted(threat_types.items(), key=lambda x: -x[1]):
        sev, col = SEVERITY_MAP.get(ttype, ('?', Fore.WHITE))
        print(col + f"    {ttype:25s} → {count:4d} events  [{sev}]")

    results_df = pd.DataFrame(results_list)

    if save_results_path:
        os.makedirs(os.path.dirname(save_results_path), exist_ok=True)
        results_df.to_csv(save_results_path, index=False)
        print(Fore.CYAN + f"\n[SAVED] Detection results → {save_results_path}")

    return results_df


# ─────────────────────────────────────────────────────────
# Quick self-test when run directly
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, "src")
    from data_loader import generate_synthetic_dataset
    from preprocessor import full_pipeline, engineer_features, clean_data
    from model_trainer import train_supervised_models, train_isolation_forest

    # Train
    df = generate_synthetic_dataset(n_normal=2000, n_attack=500)
    X_train, X_test, y_train, y_test, scaler, df_proc = full_pipeline(df)
    results, best = train_supervised_models(X_train, y_train, X_test, y_test)
    iso, _, _ = train_isolation_forest(X_train, X_test, y_test)

    # Load best model
    model = results[best]['model']

    # Run batch detection on 20 random test samples
    df_clean = clean_data(generate_synthetic_dataset(n_normal=15, n_attack=5))
    df_eng = engineer_features(df_clean)
    det_results = run_batch_detection(
        df_eng, model, scaler, iso,
        simulate_realtime=True,
        save_results_path="outputs/detection_results.csv"
    )
    print("\nDetection Results DataFrame shape:", det_results.shape)
