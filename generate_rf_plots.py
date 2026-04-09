# -*- coding: utf-8 -*-
"""
=============================================================
  generate_rf_plots.py
  Standalone script to force-generate the Random Forest
  confusion matrix + feature importance plots specifically.
  Run AFTER main.py has trained and saved the models.
=============================================================
"""
import sys, os
sys.path.insert(0, 'src')

import numpy as np
import matplotlib
matplotlib.use('Agg')

from data_loader    import generate_synthetic_dataset
from preprocessor   import full_pipeline, FEATURE_COLUMNS
from model_trainer  import get_models
from visualizer     import plot_confusion_matrix, plot_feature_importance, plot_roc_curve
from sklearn.metrics import f1_score
import joblib
from colorama import Fore, init
init(autoreset=True)

print(Fore.CYAN + "\n[INFO] Generating Random Forest specific plots...")

# ── Load data & preprocess ─────────────────────────────────
df = generate_synthetic_dataset(n_normal=4000, n_attack=1000)
X_train, X_test, y_train, y_test, scaler, df_proc = full_pipeline(df)

# ── Load or retrain RF model ───────────────────────────────
rf_path = "models/random_forest.pkl"
if os.path.exists(rf_path):
    rf = joblib.load(rf_path)
    print(Fore.GREEN + f"[LOADED] Random Forest from {rf_path}")
else:
    from sklearn.ensemble import RandomForestClassifier
    rf = RandomForestClassifier(n_estimators=150, max_depth=12,
                                class_weight='balanced', random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    joblib.dump(rf, rf_path)
    print(Fore.GREEN + "[TRAINED] Random Forest trained and saved.")

y_pred = rf.predict(X_test)
f1 = f1_score(y_test, y_pred)
print(Fore.GREEN + f"[RF] F1-Score = {f1:.4f}")

# ── Generate RF-specific plots ─────────────────────────────
print(Fore.CYAN + "\n[PLOT] Confusion Matrix - Random Forest")
plot_confusion_matrix(y_test, y_pred, "Random Forest")

print(Fore.CYAN + "[PLOT] Feature Importance - Random Forest")
plot_feature_importance(rf, FEATURE_COLUMNS)

print(Fore.CYAN + "[PLOT] ROC Curve - Random Forest")
proba = rf.predict_proba(X_test)[:, 1]
plot_roc_curve(y_test, proba, "Random Forest")

print(Fore.GREEN + "\n[DONE] Random Forest plots saved to outputs/")
print("  -> outputs/03_confusion_matrix_random_forest.png")
print("  -> outputs/04_roc_curve_random_forest.png")
print("  -> outputs/05_feature_importance.png")
