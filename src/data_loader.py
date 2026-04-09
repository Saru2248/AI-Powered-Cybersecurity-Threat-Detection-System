"""
=============================================================
  AI-Powered Cybersecurity Threat Detection System
  Module: data_loader.py
  Purpose: Load dataset or generate synthetic network traffic
           data that simulates real-world cyber attacks.
=============================================================
"""

import os
import numpy as np
import pandas as pd
from colorama import Fore, Style, init

init(autoreset=True)  # Enables colored terminal output

# ─────────────────────────────────────────────────────────
# SECTION 1: Synthetic Dataset Generator
# Simulates KDD Cup / CICIDS style network traffic data
# ─────────────────────────────────────────────────────────

def generate_synthetic_dataset(n_normal=4000, n_attack=1000, save_path=None):
    """
    Generate a synthetic network traffic dataset that mimics
    real-world datasets like KDD Cup 99 or CICIDS 2018.

    Parameters:
        n_normal (int): Number of normal (benign) traffic records.
        n_attack (int): Number of attack traffic records.
        save_path (str): Optional CSV path to save the dataset.

    Returns:
        pd.DataFrame: The complete synthetic dataset with labels.
    """
    np.random.seed(42)
    print(Fore.CYAN + "\n[INFO] Generating synthetic network traffic dataset...")

    # ── Normal Traffic Records ──────────────────────────────
    # Mimics regular user activity: small packet sizes,
    # moderate duration, low error rates
    normal = pd.DataFrame({
        'duration':          np.random.exponential(scale=5,  size=n_normal).round(2),
        'src_bytes':         np.random.normal(loc=1500, scale=400, size=n_normal).clip(100, 5000).astype(int),
        'dst_bytes':         np.random.normal(loc=1200, scale=350, size=n_normal).clip(100, 4000).astype(int),
        'land':              np.zeros(n_normal, dtype=int),               # 0 = not self-referencing
        'wrong_fragment':    np.random.poisson(0.01, size=n_normal),
        'urgent':            np.zeros(n_normal, dtype=int),
        'hot':               np.random.randint(0, 5, size=n_normal),
        'num_failed_logins': np.random.choice([0, 1], size=n_normal, p=[0.97, 0.03]),
        'logged_in':         np.ones(n_normal, dtype=int),
        'num_compromised':   np.zeros(n_normal, dtype=int),
        'count':             np.random.randint(1, 50, size=n_normal),
        'srv_count':         np.random.randint(1, 50, size=n_normal),
        'serror_rate':       np.random.uniform(0, 0.05, size=n_normal).round(3),
        'rerror_rate':       np.random.uniform(0, 0.05, size=n_normal).round(3),
        'same_srv_rate':     np.random.uniform(0.8, 1.0, size=n_normal).round(3),
        'diff_srv_rate':     np.random.uniform(0.0, 0.1, size=n_normal).round(3),
        'dst_host_count':    np.random.randint(100, 255, size=n_normal),
        'dst_host_srv_count':np.random.randint(50, 255, size=n_normal),
        'label':             np.zeros(n_normal, dtype=int),               # 0 = Normal
        'attack_type':       ['normal'] * n_normal
    })

    # ── Attack Traffic: DoS (Denial of Service) ─────────────
    # High packet rate, large byte counts, high error rate
    n_dos = n_attack // 4
    dos = pd.DataFrame({
        'duration':          np.random.exponential(scale=0.5,  size=n_dos).round(2),
        'src_bytes':         np.random.normal(loc=8000, scale=2000, size=n_dos).clip(1000, 20000).astype(int),
        'dst_bytes':         np.zeros(n_dos, dtype=int),
        'land':              np.random.choice([0, 1], size=n_dos, p=[0.7, 0.3]),
        'wrong_fragment':    np.random.poisson(0.5, size=n_dos),
        'urgent':            np.random.poisson(0.2, size=n_dos),
        'hot':               np.random.randint(0, 2, size=n_dos),
        'num_failed_logins': np.zeros(n_dos, dtype=int),
        'logged_in':         np.zeros(n_dos, dtype=int),
        'num_compromised':   np.zeros(n_dos, dtype=int),
        'count':             np.random.randint(200, 512, size=n_dos),
        'srv_count':         np.random.randint(200, 512, size=n_dos),
        'serror_rate':       np.random.uniform(0.8, 1.0, size=n_dos).round(3),
        'rerror_rate':       np.random.uniform(0.0, 0.1, size=n_dos).round(3),
        'same_srv_rate':     np.random.uniform(0.9, 1.0, size=n_dos).round(3),
        'diff_srv_rate':     np.random.uniform(0.0, 0.05, size=n_dos).round(3),
        'dst_host_count':    np.random.randint(1, 10, size=n_dos),
        'dst_host_srv_count':np.random.randint(1, 10, size=n_dos),
        'label':             np.ones(n_dos, dtype=int),
        'attack_type':       ['dos'] * n_dos
    })

    # ── Attack Traffic: Probe / Port Scan ───────────────────
    # Low bytes, many different services, high diff_srv_rate
    n_probe = n_attack // 4
    probe = pd.DataFrame({
        'duration':          np.random.uniform(0, 0.1,  size=n_probe).round(2),
        'src_bytes':         np.random.normal(loc=200, scale=50, size=n_probe).clip(10, 500).astype(int),
        'dst_bytes':         np.random.normal(loc=100, scale=30, size=n_probe).clip(0, 300).astype(int),
        'land':              np.zeros(n_probe, dtype=int),
        'wrong_fragment':    np.zeros(n_probe, dtype=int),
        'urgent':            np.zeros(n_probe, dtype=int),
        'hot':               np.random.randint(0, 3, size=n_probe),
        'num_failed_logins': np.zeros(n_probe, dtype=int),
        'logged_in':         np.zeros(n_probe, dtype=int),
        'num_compromised':   np.zeros(n_probe, dtype=int),
        'count':             np.random.randint(100, 512, size=n_probe),
        'srv_count':         np.random.randint(1, 20, size=n_probe),
        'serror_rate':       np.random.uniform(0.0, 0.3, size=n_probe).round(3),
        'rerror_rate':       np.random.uniform(0.4, 1.0, size=n_probe).round(3),
        'same_srv_rate':     np.random.uniform(0.0, 0.2, size=n_probe).round(3),
        'diff_srv_rate':     np.random.uniform(0.7, 1.0, size=n_probe).round(3),
        'dst_host_count':    np.random.randint(1, 255, size=n_probe),
        'dst_host_srv_count':np.random.randint(1, 30, size=n_probe),
        'label':             np.ones(n_probe, dtype=int),
        'attack_type':       ['probe'] * n_probe
    })

    # ── Attack Traffic: Brute Force ─────────────────────────
    # Many failed logins, moderate traffic, login flag off
    n_brute = n_attack // 4
    brute = pd.DataFrame({
        'duration':          np.random.exponential(scale=2, size=n_brute).round(2),
        'src_bytes':         np.random.normal(loc=600, scale=200, size=n_brute).clip(100, 2000).astype(int),
        'dst_bytes':         np.random.normal(loc=400, scale=100, size=n_brute).clip(50, 1000).astype(int),
        'land':              np.zeros(n_brute, dtype=int),
        'wrong_fragment':    np.zeros(n_brute, dtype=int),
        'urgent':            np.zeros(n_brute, dtype=int),
        'hot':               np.random.randint(0, 10, size=n_brute),
        'num_failed_logins': np.random.randint(3, 20, size=n_brute),
        'logged_in':         np.zeros(n_brute, dtype=int),
        'num_compromised':   np.random.randint(0, 5, size=n_brute),
        'count':             np.random.randint(30, 100, size=n_brute),
        'srv_count':         np.random.randint(1, 10, size=n_brute),
        'serror_rate':       np.random.uniform(0.0, 0.2, size=n_brute).round(3),
        'rerror_rate':       np.random.uniform(0.5, 1.0, size=n_brute).round(3),
        'same_srv_rate':     np.random.uniform(0.5, 1.0, size=n_brute).round(3),
        'diff_srv_rate':     np.random.uniform(0.0, 0.3, size=n_brute).round(3),
        'dst_host_count':    np.random.randint(1, 50, size=n_brute),
        'dst_host_srv_count':np.random.randint(1, 20, size=n_brute),
        'label':             np.ones(n_brute, dtype=int),
        'attack_type':       ['brute_force'] * n_brute
    })

    # ── Attack Traffic: Data Exfiltration / R2L ─────────────
    # High dst_bytes (data being sent out), long sessions
    n_r2l = n_attack - n_dos - n_probe - n_brute
    r2l = pd.DataFrame({
        'duration':          np.random.normal(loc=50, scale=20, size=n_r2l).clip(10, 200).round(2),
        'src_bytes':         np.random.normal(loc=1000, scale=300, size=n_r2l).clip(200, 3000).astype(int),
        'dst_bytes':         np.random.normal(loc=9000, scale=3000, size=n_r2l).clip(2000, 30000).astype(int),
        'land':              np.zeros(n_r2l, dtype=int),
        'wrong_fragment':    np.zeros(n_r2l, dtype=int),
        'urgent':            np.zeros(n_r2l, dtype=int),
        'hot':               np.random.randint(5, 30, size=n_r2l),
        'num_failed_logins': np.random.choice([0, 1], size=n_r2l, p=[0.8, 0.2]),
        'logged_in':         np.ones(n_r2l, dtype=int),
        'num_compromised':   np.random.randint(1, 20, size=n_r2l),
        'count':             np.random.randint(1, 30, size=n_r2l),
        'srv_count':         np.random.randint(1, 15, size=n_r2l),
        'serror_rate':       np.random.uniform(0.0, 0.1, size=n_r2l).round(3),
        'rerror_rate':       np.random.uniform(0.0, 0.1, size=n_r2l).round(3),
        'same_srv_rate':     np.random.uniform(0.5, 1.0, size=n_r2l).round(3),
        'diff_srv_rate':     np.random.uniform(0.0, 0.2, size=n_r2l).round(3),
        'dst_host_count':    np.random.randint(1, 30, size=n_r2l),
        'dst_host_srv_count':np.random.randint(1, 20, size=n_r2l),
        'label':             np.ones(n_r2l, dtype=int),
        'attack_type':       ['r2l_exfiltration'] * n_r2l
    })

    # ── Combine and shuffle all records ─────────────────────
    df = pd.concat([normal, dos, probe, brute, r2l], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(Fore.GREEN + f"[OK] Dataset generated: {len(df)} records")
    print(Fore.YELLOW + f"     Normal: {n_normal}  |  Attack: {n_attack}")

    attack_counts = df['attack_type'].value_counts()
    for atype, count in attack_counts.items():
        print(f"     {atype:25s} → {count} records")

    # ── Optionally save to CSV ───────────────────────────────
    if save_path:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        df.to_csv(save_path, index=False)
        print(Fore.CYAN + f"[SAVED] Dataset saved → {save_path}")

    return df


# ─────────────────────────────────────────────────────────
# SECTION 2: Load from CSV (real or previously saved data)
# ─────────────────────────────────────────────────────────

def load_dataset(filepath):
    """
    Load a CSV dataset from disk.

    Parameters:
        filepath (str): Path to the CSV file.

    Returns:
        pd.DataFrame or None
    """
    if not os.path.exists(filepath):
        print(Fore.RED + f"[ERROR] File not found: {filepath}")
        return None

    print(Fore.CYAN + f"\n[INFO] Loading dataset from: {filepath}")
    df = pd.read_csv(filepath)
    print(Fore.GREEN + f"[OK] Loaded {len(df)} rows × {len(df.columns)} columns")
    return df


# ─────────────────────────────────────────────────────────
# Quick self-test when run directly
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    df = generate_synthetic_dataset(
        n_normal=4000,
        n_attack=1000,
        save_path="data/raw/network_traffic.csv"
    )
    print("\nSample Records:")
    print(df.head(5).to_string())
    print(f"\nShape: {df.shape}")
    print(f"\nLabel distribution:\n{df['label'].value_counts()}")
