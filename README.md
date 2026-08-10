# Cognitive Security Operations
## Evaluating AI-Powered MITRE ATT&CK Technique Detection for Autonomous Threat Hunting

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)

> **MSc Thesis Research Project** | AI · Cybersecurity · SOC Automation
> SRH University of Applied Sciences · 2026

---

## Overview

SOC analysts spend 30–60 minutes manually mapping alerts to MITRE ATT&CK techniques. This thesis investigates whether **supervised Machine Learning can automate this classification** from security logs, enabling autonomous threat hunting.

## Research Questions

1. Can supervised ML accurately classify security logs into MITRE ATT&CK techniques?
2. Which log features are most informative for distinguishing techniques?
3. How does performance vary across techniques, and can class imbalance be mitigated?
4. Can SHAP-based explainability make AI-driven classification transparent for SOC use?

## Dataset: 6 ATT&CK Techniques

| Tactic | Technique ID | Technique Name | Log Source |
|--------|-------------|----------------|------------|
| Initial Access | T1566.001 | Phishing | windows-sysmon |
| Credential Access | T1110.003 | Brute Force | windows-security |
| Execution | T1059.001 | PowerShell | windows-powershell |
| Persistence | T1055 | Process Injection | windows-sysmon |
| Discovery | T1082 | System Information Discovery | windows-sysmon |
| Lateral Movement | T1021.002 | Remote Services | windows-security |

**Source:** [Splunk Attack Data](https://github.com/splunk/attack_data)

## ML Pipeline

```
Raw Logs → Feature Extraction → Preprocessing → 5 Models + CV → SHAP Explainability
```

**Models:** Logistic Regression, Decision Tree, Random Forest, XGBoost, MLP Neural Network

**Evaluation:** Stratified 5-fold Cross-Validation, Per-technique Precision/Recall/F1, SHAP

## Repository Structure

```
├── data/
│   ├── raw/              # Splunk attack logs (not committed)
│   └── processed/        # Feature matrices (not committed)
├── notebooks/
│   ├── 01_data_exploration.ipynb
│   ├── 02_preprocessing.ipynb
│   ├── 03_model_training.ipynb
│   ├── 04_evaluation.ipynb
│   ├── 05_shap_explainability.ipynb
│   └── 06_generate_figures.ipynb
├── results/
│   ├── figures/          # Thesis-ready PNG charts
│   └── *.csv             # Metrics tables
├── download_splunk_data.py
├── requirements.txt
└── README.md
```

## Quick Start

```bash
pip install -r requirements.txt
python download_splunk_data.py
```

Then run notebooks in order: `01` → `02` → `03` → `04` → `05` → `06`

## Key References

1. MITRE ATT&CK Framework — https://attack.mitre.org
2. Splunk Attack Data — https://github.com/splunk/attack_data
3. SHAP Documentation — https://shap.readthedocs.io
