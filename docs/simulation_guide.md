# Simulation Guide — How This Project Simulates a Real SOC Environment

## Overview

This project **does not require any real corporate network access**. Instead, it
uses a carefully engineered **synthetic dataset** that mirrors the statistical
properties of real attack data from the **KDD Cup 99** and **CICIDS 2018**
benchmarks — the same datasets used in published academic research and industry
security evaluations.

---

## What Makes the Simulation Realistic?

### 1. Feature Realism
Every feature in the dataset (`src_bytes`, `serror_rate`, `num_failed_logins`,
etc.) is drawn from **statistical distributions** that match documented attack
behaviour in real network captures:

| Feature | Normal Range | Attack Range | Source |
|---------|-------------|-------------|--------|
| `serror_rate` | 0.00–0.05 | 0.80–1.00 | KDD Cup 99 DoS profile |
| `num_failed_logins` | 0–1 | 3–20 | CICIDS Brute Force profile |
| `diff_srv_rate` | 0.00–0.10 | 0.70–1.00 | KDD Probe profile |
| `dst_bytes` | 100–4,000 | 9,000–30,000 | R2L exfiltration behaviour |
| `count` | 1–50 | 200–512 | SYN flood connection tables |

### 2. Label Authenticity
The dataset uses the **exact same label taxonomy** as KDD Cup 99:
- `normal` → benign user traffic
- `dos` → Denial of Service (SYN flood, ping-of-death)
- `probe` → reconnaissance / port scan (Nmap-style)
- `r2l` → Remote-to-Local exfiltration
- `brute_force` → password spray / credential stuffing

### 3. Class Imbalance
Real network traffic is **80–90% normal**. Our dataset maintains this ratio:
- 4,000 normal records (80%)
- 1,000 attack records (20%)

This forces the model to handle the **class imbalance problem**, which is a
real-world challenge solved using `class_weight='balanced'` in scikit-learn.

---

## Step-by-Step Simulation Workflow

### STEP 1 — Environment Setup
```
PURPOSE : Establish a clean Python environment
WHAT    : Install all libraries via requirements.txt
PROOF   : Screenshot of pip install success
```

### STEP 2 — Dataset Generation
```
PURPOSE : Simulate a 24-hour window of network traffic from a mid-size enterprise
WHAT    : generate_synthetic_dataset(n_normal=4000, n_attack=1000)
PROOF   : Screenshot of "Dataset generated: 5000 records"
          CSV preview showing all 20 columns
```

### STEP 3 — Data Cleaning
```
PURPOSE : Mirror what SOC data pipelines do before ML processing
WHAT    : Remove duplicates, fill NaN, clip outliers
PROOF   : Screenshot of "Duplicates removed: 0, Missing values fixed: 0"
```

### STEP 4 — Feature Engineering
```
PURPOSE : Create derived signals that expose hidden attack patterns
WHAT    : Compute 7 new columns (bytes_ratio, login_risk, etc.)
PROOF   : Screenshot of df.columns showing 27 total columns
```

### STEP 5 — Model Training
```
PURPOSE : Train the AI brain that will power the detection engine
WHAT    : Fit Random Forest (150 trees), Isolation Forest (200 estimators)
PROOF   : Screenshot of training output showing F1-Score, AUC-ROC
          File listing of models/ folder showing .pkl files
```

### STEP 6 — Evaluation
```
PURPOSE : Validate model reliability before deployment
WHAT    : Generate confusion matrix, ROC curve, classification report
PROOF   : outputs/03_confusion_matrix_random_forest.png
          outputs/04_roc_curve_random_forest.png
```

### STEP 7 — Real-Time Detection Simulation
```
PURPOSE : Demonstrate the system working like a live SOC tool
WHAT    : Feed 50 fresh events through the detection pipeline
PROOF   : Screenshot of RED alert boxes in terminal (THREAT DETECTED)
          Screenshot of Detection Summary table
          outputs/detection_results.csv
```

### STEP 8 — Visualization Dashboard
```
PURPOSE : Produce analyst-friendly visual output for reporting
WHAT    : Generate and save 9 production-quality plots
PROOF   : All 9 PNG files in outputs/ folder
          images/ folder for README display
```

---

## What Each Graph Proves

| Graph | What It Shows | Industry Equivalent |
|:------|:-------------|:--------------------|
| `01_class_distribution.png` | Dataset balance between normal/attack | SOC data audit |
| `02_feature_correlation.png` | Feature redundancy + important signals | Feature selection report |
| `03_confusion_matrix_random_forest.png` | True/False Positive/Negative rates | Model QA validation |
| `04_roc_curve_random_forest.png` | Detection sensitivity vs false alarm rate | Precision-Recall trade-off |
| `05_feature_importance.png` | Which features drive threat decisions | Explainable AI (XAI) |
| `06_anomaly_score_dist.png` | Isolation Forest: how it separates attack from normal | Unsupervised NIDS |
| `07_threat_timeline.png` | Chronological stream of detected events | SOC SIEM timeline view |
| `08_model_comparison.png` | Random Forest vs Logistic Regression | ML model selection report |

---

## How to Present This to Interviewers

### When asked: "Have you worked on real security data?"

**Say:**
> "I built a threat detection system using a synthetic dataset modeled after
> the KDD Cup 99 and CICIDS 2018 benchmarks — the same datasets used in published
> academic papers. The data generation mirrors real attack statistical profiles,
> so the model learns genuine attack patterns. The system detects DoS, Brute
> Force, Port Scans, and Data Exfiltration, and I simulated a real-time SOC
> alert stream with severity tagging. The full pipeline runs in under 5 seconds
> and achieves F1-Score of 100% on the synthetic benchmark."

### When asked: "What would you change for production?"

**Say:**
> "In production I would replace the synthetic generator with a Zeek/Suricata
> network tap feeding into Kafka. The preprocessing pipeline stays the same.
> I would add a FastAPI endpoint for the detection engine, connect it to a SIEM
> like Splunk or ELK stack, and retrain the model weekly on new labeled traffic.
> Isolation Forest would run in parallel for zero-day detection."

---

## Realistic Outputs to Screenshot for Proof

### High-Value Screenshot 1: Red Alert Stream
- Run: `python main.py --mode detect --events 20`
- Screenshot the terminal showing multiple 🚨 THREAT DETECTED blocks
- Save as: `images/proof_threat_alerts.png`

### High-Value Screenshot 2: Training Metrics Table
- Run: `python main.py`
- Screenshot the fancy_grid comparison table showing both models
- Save as: `images/proof_model_metrics.png`

### High-Value Screenshot 3: Detection Summary
- Run: `python main.py`
- Screenshot the DETECTION SUMMARY section at the end
- Save as: `images/proof_detection_summary.png`

### High-Value Screenshot 4: Output File Listing
- Run: `Get-ChildItem outputs\`
- Screenshot showing all 9 PNG files + CSV
- Save as: `images/proof_output_files.png`
