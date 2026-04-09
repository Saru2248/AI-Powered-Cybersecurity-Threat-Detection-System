"""
=============================================================
  AI-Powered Cybersecurity Threat Detection System
  Module: model_trainer.py
  Purpose: Train, evaluate, and save ML models for threat
           detection. Uses Isolation Forest (unsupervised)
           + Random Forest (supervised) ensemble approach.
=============================================================
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
    roc_auc_score
)
from colorama import Fore, init
from tabulate import tabulate

init(autoreset=True)


# ─────────────────────────────────────────────────────────
# SECTION 1: Model Definitions
# ─────────────────────────────────────────────────────────

def get_models():
    """
    Return a dictionary of ML models to train and compare.
    Each model is configured with sensible defaults.

    Three models:
    1. Logistic Regression  – Simple baseline (linear)
    2. Random Forest        – Powerful ensemble (our primary model)
    3. Isolation Forest     – Unsupervised anomaly detection
    """
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced'   # Handles class imbalance
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=150,          # Number of decision trees
            max_depth=12,              # Prevents overfitting
            min_samples_split=5,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1                  # Use all CPU cores
        )
    }
    return models


# ─────────────────────────────────────────────────────────
# SECTION 2: Train Supervised Models
# ─────────────────────────────────────────────────────────

def train_supervised_models(X_train, y_train, X_test, y_test,
                            save_dir="models"):
    """
    Train and evaluate all supervised models.
    Saves the best model (highest F1-score) to disk.

    Parameters:
        X_train, y_train: Training data
        X_test, y_test:   Evaluation data
        save_dir (str):   Directory to save models

    Returns:
        dict: results for each model
        best_model_name (str)
    """
    os.makedirs(save_dir, exist_ok=True)
    models = get_models()
    results = {}

    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.CYAN + "  TRAINING SUPERVISED MODELS")
    print(Fore.CYAN + "="*60)

    for name, model in models.items():
        print(Fore.YELLOW + f"\n[TRAINING] {name}...")

        # Train model
        model.fit(X_train, y_train)

        # Predict on test set
        y_pred = model.predict(X_test)

        # Calculate metrics
        acc  = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec  = recall_score(y_test, y_pred, zero_division=0)
        f1   = f1_score(y_test, y_pred, zero_division=0)
        auc  = roc_auc_score(y_test, y_pred)
        cm   = confusion_matrix(y_test, y_pred)

        results[name] = {
            'model':     model,
            'y_pred':    y_pred,
            'accuracy':  acc,
            'precision': prec,
            'recall':    rec,
            'f1_score':  f1,
            'auc':       auc,
            'confusion_matrix': cm
        }

        # Print results to console
        print(Fore.GREEN + f"  ✓ Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
        print(Fore.GREEN + f"  ✓ Precision : {prec:.4f}")
        print(Fore.GREEN + f"  ✓ Recall    : {rec:.4f}")
        print(Fore.GREEN + f"  ✓ F1-Score  : {f1:.4f}")
        print(Fore.GREEN + f"  ✓ AUC-ROC   : {auc:.4f}")
        print(f"\n  Confusion Matrix:\n  {cm}")

        # Save each model
        model_path = os.path.join(save_dir, f"{name.replace(' ', '_').lower()}.pkl")
        joblib.dump(model, model_path)
        print(Fore.CYAN + f"  [SAVED] → {model_path}")

    # ── Comparison Table ─────────────────────────────────
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.CYAN + "  MODEL COMPARISON TABLE")
    print(Fore.CYAN + "="*60)

    table = []
    for name, r in results.items():
        table.append([
            name,
            f"{r['accuracy']*100:.2f}%",
            f"{r['precision']:.4f}",
            f"{r['recall']:.4f}",
            f"{r['f1_score']:.4f}",
            f"{r['auc']:.4f}"
        ])

    headers = ["Model", "Accuracy", "Precision", "Recall", "F1-Score", "AUC-ROC"]
    print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

    # ── Select Best Model ─────────────────────────────────
    best_name = max(results, key=lambda k: results[k]['f1_score'])
    print(Fore.GREEN + f"\n[BEST MODEL] → {best_name}  "
          f"(F1={results[best_name]['f1_score']:.4f})")

    # Save best model separately
    best_path = os.path.join(save_dir, "best_model.pkl")
    joblib.dump(results[best_name]['model'], best_path)
    print(Fore.CYAN + f"[SAVED] Best model → {best_path}")

    return results, best_name


# ─────────────────────────────────────────────────────────
# SECTION 3: Isolation Forest (Anomaly Detection)
# Works without labels – detects "unusual" behaviour
# ─────────────────────────────────────────────────────────

def train_isolation_forest(X_train, X_test, y_test,
                           contamination=0.15,
                           save_dir="models"):
    """
    Train an Isolation Forest for unsupervised anomaly
    detection. Isolation Forest isolates anomalies by
    randomly selecting a feature and then randomly selecting
    a split value between the maximum and minimum of the
    selected feature.

    Parameters:
        X_train: Training features (no labels needed)
        X_test:  Test features
        y_test:  True labels (for evaluation only)
        contamination (float): Expected % of anomalies
        save_dir (str): Where to save the model

    Returns:
        iso_forest model, predictions array
    """
    os.makedirs(save_dir, exist_ok=True)

    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.CYAN + "  TRAINING ISOLATION FOREST (Anomaly Detector)")
    print(Fore.CYAN + "="*60)

    iso_forest = IsolationForest(
        n_estimators=200,
        contamination=contamination,   # 15% expected anomalies
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )

    print(Fore.YELLOW + "[TRAINING] Fitting Isolation Forest...")
    iso_forest.fit(X_train)        # No labels required!

    # Predict: Isolation Forest returns -1 (anomaly) or +1 (normal)
    # We convert to 0 (normal) and 1 (attack) to match our labels
    raw_pred = iso_forest.predict(X_test)
    y_pred = np.where(raw_pred == -1, 1, 0)

    # Anomaly scores (more negative = more anomalous)
    scores = iso_forest.decision_function(X_test)

    # Evaluate
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)

    print(Fore.GREEN + f"\n  ✓ Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
    print(Fore.GREEN + f"  ✓ Precision : {prec:.4f}")
    print(Fore.GREEN + f"  ✓ Recall    : {rec:.4f}")
    print(Fore.GREEN + f"  ✓ F1-Score  : {f1:.4f}")
    print(f"\n  Confusion Matrix:\n  {confusion_matrix(y_test, y_pred)}")

    # Save model
    model_path = os.path.join(save_dir, "isolation_forest.pkl")
    joblib.dump(iso_forest, model_path)
    print(Fore.CYAN + f"[SAVED] → {model_path}")

    return iso_forest, y_pred, scores


# ─────────────────────────────────────────────────────────
# SECTION 4: Load Saved Model
# ─────────────────────────────────────────────────────────

def load_model(model_path):
    """
    Load a previously saved model from disk.

    Parameters:
        model_path (str): Path to .pkl file

    Returns:
        Loaded model or None
    """
    if not os.path.exists(model_path):
        print(Fore.RED + f"[ERROR] Model not found: {model_path}")
        return None
    model = joblib.load(model_path)
    print(Fore.GREEN + f"[LOADED] Model → {model_path}")
    return model


# ─────────────────────────────────────────────────────────
# SECTION 5: Detailed Evaluation Report
# ─────────────────────────────────────────────────────────

def print_full_report(y_test, y_pred, model_name="Model"):
    """
    Print a detailed classification report.
    """
    print(Fore.CYAN + f"\n[REPORT] Full Classification Report – {model_name}")
    print(classification_report(
        y_test, y_pred,
        target_names=["Normal Traffic", "Attack/Threat"],
        digits=4
    ))


# ─────────────────────────────────────────────────────────
# Quick self-test when run directly
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, "src")
    from data_loader import generate_synthetic_dataset
    from preprocessor import full_pipeline

    df = generate_synthetic_dataset(n_normal=2000, n_attack=800)
    X_train, X_test, y_train, y_test, scaler, df_proc = full_pipeline(df)

    results, best = train_supervised_models(X_train, y_train, X_test, y_test)
    iso, iso_pred, scores = train_isolation_forest(X_train, X_test, y_test)
    print_full_report(y_test, results[best]['y_pred'], best)
