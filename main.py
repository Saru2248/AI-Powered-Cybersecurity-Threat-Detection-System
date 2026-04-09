# -*- coding: utf-8 -*-
"""
=============================================================
  AI-Powered Cybersecurity Threat Detection System
  File: main.py
  Purpose: Master orchestration script — runs the entire
           pipeline from data generation to threat detection
           and visualization in one command.

  Usage:
      python main.py
      python main.py --mode train
      python main.py --mode detect --events 50
=============================================================
"""

import os
import sys
import time
import argparse
import numpy as np
import joblib
from colorama import Fore, Back, Style, init

# ── Add /src to path for imports ──────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from data_loader   import generate_synthetic_dataset, load_dataset
from preprocessor  import full_pipeline, clean_data, engineer_features, \
                          prepare_features, FEATURE_COLUMNS
from model_trainer import (train_supervised_models, train_isolation_forest,
                           load_model, print_full_report)
from threat_detector import (load_detector_components, run_batch_detection,
                              detect_single_event, print_alert)
from visualizer    import (plot_class_distribution, plot_feature_correlation,
                           plot_confusion_matrix, plot_feature_importance,
                           plot_anomaly_scores, plot_model_comparison,
                           plot_threat_timeline)

init(autoreset=True)

# ─────────────────────────────────────────────────────────
# BANNER  (plain ASCII – works on all Windows terminals)
# ─────────────────────────────────────────────────────────

def print_banner():
    print(Fore.CYAN  + "="*70)
    print(Fore.CYAN  + "  ___  _   _____ _   _ ____  _____    _  _____")
    print(Fore.CYAN  + " / _ \| | | ____| \ | |  _ \|_   _|  | ||  _  |")
    print(Fore.CYAN  + "| |_| | | |  _| |  \| | |_) | | |    | || | | |")
    print(Fore.CYAN  + "|  _  | |_| |___| |\  |  _ <  | |    | || |_| |")
    print(Fore.CYAN  + "|_| |_|_____|____|_| \_|_| \_\ |_|    |_||_____|")
    print(Fore.RED   + "")
    print(Fore.RED   + "  CYBER THREAT DETECTION SYSTEM")
    print(Fore.CYAN  + "="*70)
    print(Fore.YELLOW + "  AI-Powered Cybersecurity Threat Detection System")
    print(Fore.YELLOW + "  Models : Random Forest + Isolation Forest + Rule Engine")
    print(Fore.YELLOW + "  Dataset: Synthetic KDD Cup-style Network Traffic (5000 records)")
    print(Fore.CYAN  + "="*70)
    print()


# ─────────────────────────────────────────────────────────
# PIPELINE STEP 1: Setup Directories
# ─────────────────────────────────────────────────────────

def setup_dirs():
    for d in ['data/raw', 'data/processed', 'models', 'outputs', 'images']:
        os.makedirs(d, exist_ok=True)
    print(Fore.GREEN + "[SETUP] Directories ready.")


# ─────────────────────────────────────────────────────────
# FULL PIPELINE: Train + Detect + Visualize
# ─────────────────────────────────────────────────────────

def run_full_pipeline(n_events_detect=50):
    """
    Orchestrates the complete ML security pipeline:
    1. Generate / load dataset
    2. Preprocess (clean, engineer, scale, split)
    3. Train models (Random Forest, Logistic Regression,
                     Isolation Forest)
    4. Evaluate and compare models
    5. Run simulated real-time threat detection
    6. Generate all visualization plots
    """
    start_time = time.time()

    print_banner()
    setup_dirs()

    # ── PHASE 1: Data Generation ──────────────────────────
    print(Fore.CYAN + "\n" + "─"*60)
    print(Fore.CYAN + "  PHASE 1 │ DATA GENERATION")
    print(Fore.CYAN + "─"*60)

    csv_path = "data/raw/network_traffic.csv"

    if os.path.exists(csv_path):
        print(Fore.YELLOW + f"[INFO] Found existing dataset: {csv_path}")
        df = load_dataset(csv_path)
    else:
        df = generate_synthetic_dataset(
            n_normal=4000,
            n_attack=1000,
            save_path=csv_path
        )

    print(f"\n  Dataset shape : {df.shape}")
    print(f"  Columns       : {list(df.columns)}")
    print(f"\n  First 3 rows:")
    print(df.head(3).to_string(index=False))

    # ── PHASE 2–4: Preprocessing Pipeline ────────────────
    print(Fore.CYAN + "\n" + "─"*60)
    print(Fore.CYAN + "  PHASE 2–4 │ PREPROCESSING & FEATURE ENGINEERING")
    print(Fore.CYAN + "─"*60)

    X_train, X_test, y_train, y_test, scaler, df_proc = full_pipeline(
        df, save_scaler_path="models/scaler.pkl"
    )

    # ── PHASE 5: Model Training ───────────────────────────
    print(Fore.CYAN + "\n" + "─"*60)
    print(Fore.CYAN + "  PHASE 5 │ MODEL TRAINING")
    print(Fore.CYAN + "─"*60)

    results, best_name = train_supervised_models(
        X_train, y_train, X_test, y_test, save_dir="models"
    )

    iso_forest, iso_pred, iso_scores = train_isolation_forest(
        X_train, X_test, y_test,
        contamination=0.17,         # ~17% attack rate in our dataset
        save_dir="models"
    )

    # ── PHASE 6: Evaluation ───────────────────────────────
    print(Fore.CYAN + "\n" + "─"*60)
    print(Fore.CYAN + "  PHASE 6 │ MODEL EVALUATION")
    print(Fore.CYAN + "─"*60)

    print_full_report(y_test, results[best_name]['y_pred'], best_name)

    # ── PHASE 7: Threat Detection Simulation ─────────────
    print(Fore.CYAN + "\n" + "─"*60)
    print(Fore.CYAN + "  PHASE 7 │ REAL-TIME THREAT DETECTION SIMULATION")
    print(Fore.CYAN + "─"*60)

    # Use a fresh batch for detection simulation
    df_sim = generate_synthetic_dataset(
        n_normal=max(1, n_events_detect - 15),
        n_attack=15
    )
    df_sim = clean_data(df_sim)
    df_sim = engineer_features(df_sim)

    best_model = results[best_name]['model']

    det_results = run_batch_detection(
        df_sim,
        best_model,
        scaler,
        iso=iso_forest,
        simulate_realtime=False,
        save_results_path="outputs/detection_results.csv"
    )

    # ── PHASE 8: Visualization ────────────────────────────
    print(Fore.CYAN + "\n" + "─"*60)
    print(Fore.CYAN + "  PHASE 8 │ VISUALIZATION")
    print(Fore.CYAN + "─"*60)

    plot_class_distribution(df_proc)
    plot_feature_correlation(df_proc)
    plot_confusion_matrix(y_test, results[best_name]['y_pred'], best_name)
    plot_feature_importance(best_model, FEATURE_COLUMNS)
    plot_anomaly_scores(iso_scores, y_test)
    plot_model_comparison({k: v for k, v in results.items()})

    if 'event_id' in det_results.columns:
        plot_threat_timeline(det_results)

    # ── ROC Curve (Random Forest has predict_proba) ───────
    if hasattr(best_model, 'predict_proba'):
        from visualizer import plot_roc_curve
        proba = best_model.predict_proba(X_test)[:, 1]
        plot_roc_curve(y_test, proba, best_name)

    # ── FINAL SUMMARY ──────────────────────────────────────
    elapsed = time.time() - start_time
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.GREEN + "  ✅ PIPELINE COMPLETE!")
    print(Fore.CYAN + "="*60)
    print(f"  Total time        : {elapsed:.1f} seconds")
    print(f"  Best model        : {best_name}")
    print(f"  Best F1-Score     : {results[best_name]['f1_score']:.4f}")
    print(f"  Plots saved       : outputs/  (8 PNG files)")
    print(f"  Saved models      : models/   (best_model.pkl, scaler.pkl)")
    print(f"  Detection log     : outputs/detection_results.csv")
    print(Fore.CYAN + "="*60)
    print(Fore.YELLOW + "\n  [OUTPUT] Check the 'outputs/' folder for all visualization graphs.")
    print(Fore.YELLOW + "  [PROOF]  Use these graphs as screenshots for your GitHub README.")
    print(Fore.CYAN + "="*60 + "\n")


# ─────────────────────────────────────────────────────────
# DETECT-ONLY MODE: Load saved model to detect new events
# ─────────────────────────────────────────────────────────

def run_detect_mode(n_events=20):
    """
    Load trained models from disk and run detection on
    fresh synthetic events. Use this after training to
    demonstrate the live detection capability.
    """
    print_banner()
    print(Fore.CYAN + "\n[DETECT MODE] Loading pre-trained models...")

    model, scaler, iso = load_detector_components()

    if model is None or scaler is None:
        print(Fore.RED + "\n[ERROR] Models not found. Run 'python main.py --mode train' first!")
        sys.exit(1)

    df_new = generate_synthetic_dataset(
        n_normal=max(1, n_events - 8),
        n_attack=8
    )
    df_new = clean_data(df_new)
    df_new = engineer_features(df_new)

    run_batch_detection(
        df_new, model, scaler, iso,
        simulate_realtime=True,
        save_results_path="outputs/live_detection.csv"
    )


# ─────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AI-Powered Cybersecurity Threat Detection System"
    )
    parser.add_argument(
        '--mode',
        choices=['full', 'train', 'detect'],
        default='full',
        help="'full' = train + detect + visualize (default) | "
             "'train' = training only | 'detect' = detection only"
    )
    parser.add_argument(
        '--events',
        type=int,
        default=50,
        help="Number of events to simulate in detection phase (default: 50)"
    )

    args = parser.parse_args()

    if args.mode in ('full', 'train'):
        run_full_pipeline(n_events_detect=args.events)
    elif args.mode == 'detect':
        run_detect_mode(n_events=args.events)
