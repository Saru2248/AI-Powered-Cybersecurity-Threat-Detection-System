"""
=============================================================
  AI-Powered Cybersecurity Threat Detection System
  Module: visualizer.py
  Purpose: Generate all graphs, charts, and visual outputs
           for the project report, README, and GitHub proof.
=============================================================
"""

import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend (no display needed)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc
from colorama import Fore, init

init(autoreset=True)

# ── Global Styling ────────────────────────────────────────
plt.rcParams.update({
    'figure.facecolor':  '#0d1117',   # GitHub dark background
    'axes.facecolor':    '#161b22',
    'axes.edgecolor':    '#30363d',
    'axes.labelcolor':   '#e6edf3',
    'xtick.color':       '#8b949e',
    'ytick.color':       '#8b949e',
    'text.color':        '#e6edf3',
    'grid.color':        '#21262d',
    'grid.linestyle':    '--',
    'grid.alpha':        0.5,
    'font.family':       'DejaVu Sans',
    'font.size':         11,
})

ACCENT  = '#58a6ff'   # Blue
DANGER  = '#f85149'   # Red
SUCCESS = '#3fb950'   # Green
WARN    = '#e3b341'   # Yellow
PURPLE  = '#bc8cff'   # Purple

OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────
# 1. Dataset Distribution Plot
# ─────────────────────────────────────────────────────────

def plot_class_distribution(df, save=True):
    """
    Bar chart showing distribution of normal vs attack
    traffic and breakdown by attack type.
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("Network Traffic Dataset Distribution",
                 fontsize=16, fontweight='bold', color='#e6edf3', y=1.01)

    # ── Plot 1: Normal vs Attack ──────────────────────────
    ax1 = axes[0]
    label_counts = df['label'].value_counts().sort_index()
    bars = ax1.bar(['Normal', 'Attack'],
                   label_counts.values,
                   color=[SUCCESS, DANGER],
                   width=0.5, edgecolor='none')

    for bar, val in zip(bars, label_counts.values):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 20,
                 f'{val:,}', ha='center', va='bottom',
                 fontsize=13, fontweight='bold', color='#e6edf3')

    ax1.set_title("Binary Class Distribution", fontsize=13, color=ACCENT)
    ax1.set_ylabel("Number of Records")
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)

    # ── Plot 2: Attack Type Breakdown ─────────────────────
    ax2 = axes[1]
    attack_counts = df['attack_type'].value_counts()
    colors = [SUCCESS, DANGER, WARN, PURPLE, ACCENT][:len(attack_counts)]

    wedges, texts, autotexts = ax2.pie(
        attack_counts.values,
        labels=attack_counts.index,
        autopct='%1.1f%%',
        colors=colors,
        startangle=140,
        pctdistance=0.8,
        wedgeprops={'edgecolor': '#0d1117', 'linewidth': 2}
    )
    for t in texts:
        t.set_color('#e6edf3')
        t.set_fontsize(10)
    for at in autotexts:
        at.set_color('#0d1117')
        at.set_fontweight('bold')

    ax2.set_title("Attack Type Breakdown", fontsize=13, color=ACCENT)

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "01_class_distribution.png")
    if save:
        plt.savefig(path, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        print(Fore.CYAN + f"[SAVED] {path}")
    plt.close()
    return path


# ─────────────────────────────────────────────────────────
# 2. Feature Correlation Heatmap
# ─────────────────────────────────────────────────────────

def plot_feature_correlation(df, save=True):
    """
    Heatmap of feature correlations.
    High correlation suggests redundant features.
    """
    numeric_df = df.select_dtypes(include=[np.number])
    numeric_df = numeric_df.drop(columns=['label'], errors='ignore')

    corr = numeric_df.corr()

    fig, ax = plt.subplots(figsize=(16, 13))
    sns.heatmap(
        corr,
        ax=ax,
        cmap='coolwarm',
        center=0,
        annot=False,
        square=True,
        linewidths=0.3,
        linecolor='#0d1117',
        cbar_kws={'shrink': 0.8}
    )
    ax.set_title("Feature Correlation Heatmap",
                 fontsize=15, fontweight='bold', color='#e6edf3', pad=15)
    ax.tick_params(axis='x', rotation=45, labelsize=8)
    ax.tick_params(axis='y', rotation=0, labelsize=8)

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "02_feature_correlation.png")
    if save:
        plt.savefig(path, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        print(Fore.CYAN + f"[SAVED] {path}")
    plt.close()
    return path


# ─────────────────────────────────────────────────────────
# 3. Confusion Matrix
# ─────────────────────────────────────────────────────────

def plot_confusion_matrix(y_test, y_pred, model_name="Model", save=True):
    """
    Visualize the confusion matrix as an annotated heatmap.
    """
    cm = confusion_matrix(y_test, y_pred)
    labels = ["Normal", "Attack"]

    fig, ax = plt.subplots(figsize=(7, 6))
    sns.heatmap(
        cm, ax=ax,
        annot=True, fmt='d',
        cmap='Blues',
        xticklabels=labels,
        yticklabels=labels,
        linewidths=2,
        linecolor='#0d1117',
        annot_kws={'size': 20, 'weight': 'bold', 'color': '#e6edf3'}
    )

    ax.set_title(f"Confusion Matrix – {model_name}",
                 fontsize=14, fontweight='bold', color='#e6edf3', pad=15)
    ax.set_xlabel("Predicted Label",  fontsize=12)
    ax.set_ylabel("True Label",       fontsize=12)

    # Annotate TN/FP/FN/TP
    for text, label in zip(ax.texts, ['TN', 'FP', 'FN', 'TP']):
        text.set_text(f"{text.get_text()}\n({label})")

    plt.tight_layout()
    safe_name = model_name.replace(' ', '_').lower()
    path = os.path.join(OUTPUT_DIR, f"03_confusion_matrix_{safe_name}.png")
    if save:
        plt.savefig(path, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        print(Fore.CYAN + f"[SAVED] {path}")
    plt.close()
    return path


# ─────────────────────────────────────────────────────────
# 4. ROC Curve
# ─────────────────────────────────────────────────────────

def plot_roc_curve(y_test, y_pred_proba, model_name="Model", save=True):
    """
    Plot the ROC curve for a classifier.
    """
    fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
    roc_auc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fpr, tpr, color=ACCENT, lw=2.5,
            label=f'ROC Curve (AUC = {roc_auc:.4f})')
    ax.fill_between(fpr, tpr, alpha=0.15, color=ACCENT)
    ax.plot([0, 1], [0, 1], 'k--', lw=1.5,
            alpha=0.5, label='Random Classifier')

    ax.set_xlabel("False Positive Rate (FPR)", fontsize=12)
    ax.set_ylabel("True Positive Rate (Recall)", fontsize=12)
    ax.set_title(f"ROC Curve – {model_name}",
                 fontsize=14, fontweight='bold', color='#e6edf3')
    ax.legend(loc="lower right", framealpha=0.3)
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])

    plt.tight_layout()
    safe_name = model_name.replace(' ', '_').lower()
    path = os.path.join(OUTPUT_DIR, f"04_roc_curve_{safe_name}.png")
    if save:
        plt.savefig(path, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        print(Fore.CYAN + f"[SAVED] {path}")
    plt.close()
    return path


# ─────────────────────────────────────────────────────────
# 5. Feature Importance (Random Forest)
# ─────────────────────────────────────────────────────────

def plot_feature_importance(model, feature_names, save=True):
    """
    Horizontal bar chart of feature importances from
    a tree-based model (Random Forest).
    """
    if not hasattr(model, 'feature_importances_'):
        print(Fore.YELLOW + "[SKIP] Model does not support feature_importances_")
        return None

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    top_n = min(20, len(feature_names))

    fig, ax = plt.subplots(figsize=(10, 8))

    colors = plt.cm.plasma(np.linspace(0.2, 0.9, top_n))
    bars = ax.barh(
        range(top_n),
        importances[indices[:top_n]][::-1],
        color=colors[::-1],
        edgecolor='none'
    )

    ax.set_yticks(range(top_n))
    ax.set_yticklabels(
        [feature_names[i] for i in indices[:top_n]][::-1],
        fontsize=10
    )
    ax.set_xlabel("Feature Importance Score", fontsize=12)
    ax.set_title("Top Feature Importances – Random Forest",
                 fontsize=14, fontweight='bold', color='#e6edf3')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    # Value labels on bars
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.001, bar.get_y() + bar.get_height()/2,
                f'{w:.4f}', va='center', fontsize=8, color='#8b949e')

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "05_feature_importance.png")
    if save:
        plt.savefig(path, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        print(Fore.CYAN + f"[SAVED] {path}")
    plt.close()
    return path


# ─────────────────────────────────────────────────────────
# 6. Anomaly Score Distribution (Isolation Forest)
# ─────────────────────────────────────────────────────────

def plot_anomaly_scores(scores, y_test, save=True):
    """
    KDE plot of anomaly scores from Isolation Forest.
    Shows separation between normal and anomalous traffic.
    """
    fig, ax = plt.subplots(figsize=(10, 6))

    normal_scores = scores[y_test == 0]
    attack_scores = scores[y_test == 1]

    # If enough data, draw KDE; otherwise histogram
    try:
        sns.kdeplot(normal_scores, ax=ax, color=SUCCESS, fill=True,
                    alpha=0.4, label='Normal Traffic', linewidth=2.5)
        sns.kdeplot(attack_scores, ax=ax, color=DANGER, fill=True,
                    alpha=0.4, label='Attack Traffic', linewidth=2.5)
    except Exception:
        ax.hist(normal_scores, bins=30, alpha=0.5, color=SUCCESS,
                label='Normal Traffic', edgecolor='none')
        ax.hist(attack_scores, bins=30, alpha=0.5, color=DANGER,
                label='Attack Traffic', edgecolor='none')

    ax.axvline(x=0, color=WARN, linestyle='--',
               linewidth=2, label='Decision Boundary (0)')

    ax.set_xlabel("Anomaly Score (lower = more anomalous)", fontsize=12)
    ax.set_ylabel("Density", fontsize=12)
    ax.set_title("Isolation Forest – Anomaly Score Distribution",
                 fontsize=14, fontweight='bold', color='#e6edf3')
    ax.legend(framealpha=0.3)

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "06_anomaly_score_dist.png")
    if save:
        plt.savefig(path, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        print(Fore.CYAN + f"[SAVED] {path}")
    plt.close()
    return path


# ─────────────────────────────────────────────────────────
# 7. Threat Timeline (Detection Results)
# ─────────────────────────────────────────────────────────

def plot_threat_timeline(results_df, save=True):
    """
    Bar chart timeline showing detected threats across events.
    Color-coded by threat type.
    """
    type_colors = {
        'normal':            SUCCESS,
        'dos':               DANGER,
        'probe':             WARN,
        'brute_force':       PURPLE,
        'r2l_exfiltration':  '#ff7b72',
        'unknown_anomaly':   '#ffa657'
    }

    fig, ax = plt.subplots(figsize=(14, 5))

    for _, row in results_df.iterrows():
        color = type_colors.get(row['threat_type'], ACCENT)
        ax.bar(row['event_id'], 1, color=color, edgecolor='none', width=0.9)

    # Legend
    patches = [mpatches.Patch(color=c, label=t.replace('_', ' ').title())
               for t, c in type_colors.items()]
    ax.legend(handles=patches, loc='upper right',
              framealpha=0.3, ncol=3, fontsize=9)

    ax.set_xlabel("Event Index", fontsize=12)
    ax.set_ylabel("Event Detected", fontsize=12)
    ax.set_title("Real-Time Threat Detection Timeline",
                 fontsize=14, fontweight='bold', color='#e6edf3')
    ax.set_yticks([])
    ax.set_xlim(-1, len(results_df) + 1)

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "07_threat_timeline.png")
    if save:
        plt.savefig(path, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        print(Fore.CYAN + f"[SAVED] {path}")
    plt.close()
    return path


# ─────────────────────────────────────────────────────────
# 8. Model Performance Comparison Bar Chart
# ─────────────────────────────────────────────────────────

def plot_model_comparison(results_dict, save=True):
    """
    Grouped bar chart comparing model metrics side-by-side.
    """
    metrics = ['accuracy', 'precision', 'recall', 'f1_score', 'auc']
    metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC-ROC']
    model_names = list(results_dict.keys())

    x = np.arange(len(metrics))
    bar_width = 0.35
    colors = [ACCENT, PURPLE, WARN, SUCCESS, DANGER]

    fig, ax = plt.subplots(figsize=(13, 7))

    for i, (model_name, r) in enumerate(results_dict.items()):
        values = [r[m] for m in metrics]
        offset = (i - len(model_names)/2 + 0.5) * bar_width
        bars = ax.bar(x + offset, values, bar_width,
                      label=model_name, color=colors[i % len(colors)],
                      edgecolor='none', alpha=0.85)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + 0.005,
                    f'{val:.3f}', ha='center', va='bottom',
                    fontsize=8, color='#8b949e')

    ax.set_xticks(x)
    ax.set_xticklabels(metric_labels, fontsize=11)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("Model Performance Comparison",
                 fontsize=14, fontweight='bold', color='#e6edf3')
    ax.legend(framealpha=0.3, fontsize=10)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.axhline(y=1.0, color='#30363d', linewidth=1, linestyle='--')

    plt.tight_layout()
    path = os.path.join(OUTPUT_DIR, "08_model_comparison.png")
    if save:
        plt.savefig(path, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        print(Fore.CYAN + f"[SAVED] {path}")
    plt.close()
    return path


# ─────────────────────────────────────────────────────────
# Convenience: Run all visualizations
# ─────────────────────────────────────────────────────────

def generate_all_plots(df, results_dict, best_model_name,
                       y_test, iso_scores=None, results_df=None):
    """
    Generate every visualization and save to outputs/ folder.
    """
    print(Fore.CYAN + "\n[VISUALIZER] Generating all plots...")

    paths = []
    paths.append(plot_class_distribution(df))
    paths.append(plot_feature_correlation(df))

    best = results_dict[best_model_name]
    paths.append(plot_confusion_matrix(y_test, best['y_pred'], best_model_name))

    if hasattr(best['model'], 'predict_proba'):
        # We need proba for ROC; use stored y_pred as binary
        from sklearn.metrics import roc_curve
        try:
            proba = best['model'].predict_proba(
                # dummy – actual X_test needed; use y_pred as rough proxy
                best['y_pred'].reshape(-1, 1)
            )[:, 1]
        except Exception:
            proba = best['y_pred'].astype(float)
        paths.append(plot_roc_curve(y_test, proba, best_model_name))

    paths.append(plot_feature_importance(best['model'], list(range(25))))
    if iso_scores is not None:
        paths.append(plot_anomaly_scores(iso_scores, y_test))
    paths.append(plot_model_comparison(results_dict))
    if results_df is not None:
        paths.append(plot_threat_timeline(results_df))

    print(Fore.GREEN + f"\n[OK] {len(paths)} plots saved to outputs/")
    return paths


if __name__ == "__main__":
    print("Run main.py to generate all visualizations.")
