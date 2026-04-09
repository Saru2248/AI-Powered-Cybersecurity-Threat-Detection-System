"""
=============================================================
  AI-Powered Cybersecurity Threat Detection System
  Module: preprocessor.py
  Purpose: Clean, preprocess, and engineer features from
           raw network traffic data for ML model input.
=============================================================
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from colorama import Fore, Style, init
import joblib
import os

init(autoreset=True)

# ─────────────────────────────────────────────────────────
# SECTION 1: Data Cleaning
# ─────────────────────────────────────────────────────────

def clean_data(df):
    """
    Clean the raw dataset:
    - Remove/fill missing values
    - Remove duplicate rows
    - Clip outliers using IQR method
    - Report cleaning summary

    Parameters:
        df (pd.DataFrame): Raw input data

    Returns:
        pd.DataFrame: Cleaned data
    """
    print(Fore.CYAN + "\n[PREPROCESSING] Starting data cleaning...")

    original_shape = df.shape

    # Step 1: Remove duplicate rows
    before = len(df)
    df = df.drop_duplicates()
    dupes_removed = before - len(df)
    print(f"  Duplicates removed  : {dupes_removed}")

    # Step 2: Handle missing values
    # Fill numeric NaN with median, categorical NaN with mode
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    categorical_cols = df.select_dtypes(include=['object']).columns

    missing_before = df.isnull().sum().sum()
    for col in numeric_cols:
        df[col].fillna(df[col].median(), inplace=True)
    for col in categorical_cols:
        if col not in ['label', 'attack_type']:
            df[col].fillna(df[col].mode()[0], inplace=True)

    missing_after = df.isnull().sum().sum()
    print(f"  Missing values fixed : {missing_before - missing_after}")

    # Step 3: Clip extreme outliers (only numeric feature cols)
    feature_cols = [c for c in numeric_cols if c not in ['label']]
    for col in feature_cols:
        Q1 = df[col].quantile(0.01)
        Q99 = df[col].quantile(0.99)
        df[col] = df[col].clip(lower=Q1, upper=Q99)

    print(f"  Outliers clipped    : IQR 1-99th percentile on {len(feature_cols)} features")
    print(Fore.GREEN + f"[OK] Cleaning done → {original_shape} → {df.shape}")

    return df


# ─────────────────────────────────────────────────────────
# SECTION 2: Feature Engineering
# ─────────────────────────────────────────────────────────

def engineer_features(df):
    """
    Create additional meaningful features from existing ones.
    These derived features help the model detect subtle patterns
    that raw features alone cannot capture.

    Parameters:
        df (pd.DataFrame): Cleaned data

    Returns:
        pd.DataFrame: Data with new engineered features
    """
    print(Fore.CYAN + "\n[PREPROCESSING] Engineering features...")

    # Feature 1: Bytes ratio (how much data flows back vs sent)
    # Low ratio in attacks like DoS (server doesn't respond back)
    df['bytes_ratio'] = (df['dst_bytes'] / (df['src_bytes'] + 1)).round(4)

    # Feature 2: Total bytes transferred in session
    df['total_bytes'] = df['src_bytes'] + df['dst_bytes']

    # Feature 3: Error ratio = combined error rate
    df['error_ratio'] = ((df['serror_rate'] + df['rerror_rate']) / 2).round(4)

    # Feature 4: Service similarity score
    # High sama_srv_rate = connections going to same service (flood)
    df['service_similarity'] = (df['same_srv_rate'] - df['diff_srv_rate']).round(4)

    # Feature 5: Bytes per unit time (data transfer speed)
    # High value = very fast data movement → possible exfiltration or DoS
    df['bytes_per_second'] = (df['total_bytes'] / (df['duration'] + 0.001)).round(4)

    # Feature 6: Login risk score
    # Combines failed logins with compromised count
    df['login_risk'] = (df['num_failed_logins'] * 2 + df['num_compromised']).astype(float)

    # Feature 7: Connection density (connections per host)
    df['conn_density'] = (df['count'] / (df['dst_host_count'] + 1)).round(4)

    print(f"  New features added  : bytes_ratio, total_bytes, error_ratio,")
    print(f"                        service_similarity, bytes_per_second,")
    print(f"                        login_risk, conn_density")
    print(Fore.GREEN + f"[OK] Feature engineering done → {df.shape[1]} total columns")

    return df


# ─────────────────────────────────────────────────────────
# SECTION 3: Feature Selection & Scaling
# ─────────────────────────────────────────────────────────

FEATURE_COLUMNS = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'count', 'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
    # Engineered features:
    'bytes_ratio', 'total_bytes', 'error_ratio', 'service_similarity',
    'bytes_per_second', 'login_risk', 'conn_density'
]

TARGET_COLUMN = 'label'


def prepare_features(df, scaler=None, fit_scaler=True, save_scaler_path=None):
    """
    Select feature columns, scale them using StandardScaler,
    and return X (features) and y (target labels).

    Parameters:
        df (pd.DataFrame): Engineered data
        scaler: Pre-trained scaler (None if training fresh)
        fit_scaler (bool): If True, fit scaler on this data
        save_scaler_path (str): Path to save fitted scaler

    Returns:
        X (np.ndarray), y (np.ndarray), scaler
    """
    print(Fore.CYAN + "\n[PREPROCESSING] Preparing features for model...")

    # Extract features and labels
    X = df[FEATURE_COLUMNS].values
    y = df[TARGET_COLUMN].values

    # Scale features to zero mean, unit variance
    if scaler is None:
        scaler = StandardScaler()

    if fit_scaler:
        X_scaled = scaler.fit_transform(X)
        print(f"  Scaler fitted on {X.shape[0]} samples")
    else:
        X_scaled = scaler.transform(X)
        print(f"  Scaler applied (pre-fitted) on {X.shape[0]} samples")

    # Optionally save scaler for inference reuse
    if save_scaler_path and fit_scaler:
        os.makedirs(os.path.dirname(save_scaler_path), exist_ok=True)
        joblib.dump(scaler, save_scaler_path)
        print(Fore.CYAN + f"  Scaler saved → {save_scaler_path}")

    print(Fore.GREEN + f"[OK] Features ready → X:{X_scaled.shape}  y:{y.shape}")
    print(f"     Normal={np.sum(y==0)}  Attack={np.sum(y==1)}")

    return X_scaled, y, scaler


# ─────────────────────────────────────────────────────────
# SECTION 4: Train/Test Split
# ─────────────────────────────────────────────────────────

def split_data(X, y, test_size=0.2, random_state=42):
    """
    Split scaled features and labels into training and test sets.

    Parameters:
        X (np.ndarray): Feature matrix
        y (np.ndarray): Labels
        test_size (float): Fraction for test set (default 20%)
        random_state (int): Reproducibility seed

    Returns:
        X_train, X_test, y_train, y_test
    """
    print(Fore.CYAN + "\n[PREPROCESSING] Splitting data into train/test sets...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(Fore.GREEN + f"[OK] Train: {X_train.shape}  |  Test: {X_test.shape}")
    print(f"     Train Normal={np.sum(y_train==0)}  Train Attack={np.sum(y_train==1)}")
    print(f"     Test  Normal={np.sum(y_test==0)}   Test  Attack={np.sum(y_test==1)}")

    return X_train, X_test, y_train, y_test


# ─────────────────────────────────────────────────────────
# Full preprocessing pipeline (convenience wrapper)
# ─────────────────────────────────────────────────────────

def full_pipeline(df, save_scaler_path="models/scaler.pkl"):
    """
    Run the complete preprocessing pipeline:
    clean → engineer → prepare → split

    Parameters:
        df (pd.DataFrame): Raw input DataFrame
        save_scaler_path (str): Where to persist the scaler

    Returns:
        X_train, X_test, y_train, y_test, scaler, df_processed
    """
    df = clean_data(df)
    df = engineer_features(df)
    X, y, scaler = prepare_features(df, save_scaler_path=save_scaler_path)
    X_train, X_test, y_train, y_test = split_data(X, y)

    # Save processed dataset for reference
    os.makedirs("data/processed", exist_ok=True)
    df.to_csv("data/processed/processed_traffic.csv", index=False)
    print(Fore.CYAN + "[SAVED] Processed data → data/processed/processed_traffic.csv")

    return X_train, X_test, y_train, y_test, scaler, df


# ─────────────────────────────────────────────────────────
# Quick self-test when run directly
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Test with a tiny synthetic slice
    from data_loader import generate_synthetic_dataset
    df = generate_synthetic_dataset(n_normal=500, n_attack=200)
    X_train, X_test, y_train, y_test, scaler, df_proc = full_pipeline(df)
    print(f"\nReady for model: X_train={X_train.shape}, X_test={X_test.shape}")
