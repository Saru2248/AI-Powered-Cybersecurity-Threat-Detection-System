
# 🚀 AI-Powered Cybersecurity Threat Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge\&logo=python\&logoColor=white)
![Machine Learning](https://img.shields.io/badge/ML-Random%20Forest-green?style=for-the-badge)
![Flask](https://img.shields.io/badge/Backend-Flask-black?style=for-the-badge\&logo=flask)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)

### 🔐 Real-Time Threat Detection with ML + Web Dashboard

</div>

---

## 📌 Overview

This project implements a **Machine Learning-based Intrusion Detection System (IDS)** with a **real-time web dashboard**.

It simulates how a **Security Operations Center (SOC)** detects and responds to cyber threats using:

* Supervised learning (attack classification)
* Unsupervised learning (anomaly detection)
* Live alert visualization (Flask UI)

---

## ⚡ What Makes This Project Strong

Most student projects stop at model training.
This one goes further:

* ✅ Full ML pipeline (data → training → detection)
* ✅ Real-time threat simulation engine
* ✅ Interactive **Flask dashboard**
* ✅ Visual analytics (plots + graphs)
* ✅ Modular production-style structure (`src/`, `models/`, etc.)

---

## 🧠 Features

* Detects:

  * DoS attacks
  * Port scanning (Probe)
  * Brute force attacks
  * Data exfiltration
* Identifies **unknown anomalies** using Isolation Forest
* Assigns severity:

  * CRITICAL / HIGH / MEDIUM
* Generates:

  * Confusion matrix
  * ROC curve
  * Feature importance
  * Threat timeline

---

## 🛠️ Tech Stack

| Layer           | Technology                                           |
| --------------- | ---------------------------------------------------- |
| Language        | Python                                               |
| ML Models       | Random Forest, Logistic Regression, Isolation Forest |
| Backend         | Flask                                                |
| Data Processing | Pandas, NumPy                                        |
| Visualization   | Matplotlib, Seaborn                                  |
| Model Storage   | Joblib                                               |

---

## 🏗️ Architecture

```id="arch12"
Network Traffic
      ↓
Preprocessing
      ↓
Feature Engineering
      ↓
ML Models
(RF + Isolation Forest)
      ↓
Threat Classification
      ↓
Severity Assignment
      ↓
Flask Dashboard + Alerts
```

---

## 📁 Project Structure

```id="struct99"
├── data/               # Raw & processed datasets
├── docs/               # Documentation
├── images/             # README visuals
├── models/             # Saved ML models
├── outputs/            # Generated results & plots
├── src/                # Core ML pipeline
│
├── static/css/         # Dashboard styling
├── templates/          # Flask HTML UI
│
├── app.py              # Web dashboard
├── main.py             # Pipeline controller
├── generate_rf_plots.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/AI-Cybersecurity-Threat-Detection.git
cd AI-Cybersecurity-Threat-Detection

python -m venv venv
venv\Scripts\activate   # Windows

pip install -r requirements.txt
```

---

## 🚀 Usage

### 🔹 Run Full Pipeline

```bash
python main.py
```

### 🔹 Train Model

```bash
python main.py --mode train
```

### 🔹 Run Detection

```bash
python main.py --mode detect --events 100
```

### 🔹 Launch Web Dashboard

```bash
python app.py
```

👉 Open: **[http://localhost:5000](http://localhost:5000)**

---

## 📊 Results

* High classification accuracy on structured dataset
* Effective anomaly detection for unknown threats
* Clear model interpretability via feature importance

> ⚠️ Real-world datasets will produce lower but more realistic performance (~90–97% F1)

---

## 🔍 Attack Types

| Attack       | Description      |
| ------------ | ---------------- |
| DoS          | Traffic flooding |
| Probe        | Port scanning    |
| Brute Force  | Login attacks    |
| Exfiltration | Data theft       |

---

## ⚠️ Limitations

* Synthetic dataset
* Not tested on real production traffic
* No distributed/streaming pipeline
* No deep learning models

---

## 🔮 Future Improvements

* Real datasets (CICIDS, UNSW-NB15)
* Kafka + Spark streaming
* Deep learning (LSTM / Autoencoder)
* Cloud deployment
* SIEM integration

---

## 👨‍💻 Author

**Sarthak Dhumal**

* GitHub: [https://github.com/Saru2248](https://github.com/Saru2248)
* LinkedIn: (https://www.linkedin.com/in/sarthak-dhumal-07555a211/)

---

## ⭐ Support

If this project helped you, give it a star ⭐

