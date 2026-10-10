# Fixed-Split Results: Selective Rendering & Threshold Tuning
**Task ID**: `EXP-15-SELECTIVE-RENDERING-THRESHOLD-TUNING-2026-09-16`  
**Test Partition**: $N=1,799$ samples ($1,402$ Legitimate, $397$ Phishing across $631$ domain-disjoint apex domains)  

## Fixed Split Comparison Table ($N=1,799$, Seed 42)

| Metric | Candidate A (Baseline) | Candidate B (T1 Sparse) | Candidate D (T3 Sparse+JS) | Candidate E (T4 Narrow) | Candidate F (Cascade F) | Candidate G (Learned T5) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Accuracy** | 94.55% | 94.55% | 94.55% | 94.55% | 93.61% | 94.55% |
| **Phishing Recall (>=94% req.)** | 94.21% | 94.21% | 94.21% | 94.21% | 94.46% | 94.21% |
| **Precision** | 83.30% | 83.30% | 83.30% | 83.30% | 80.13% | 83.30% |
| **F1-Score** | 88.42% | 88.42% | 88.42% | 88.42% | 86.71% | 88.42% |
| **Specificity** | 94.65% | 94.65% | 94.65% | 94.65% | 93.37% | 94.65% |
| **False Positive Rate (FPR)** | 5.35% | 5.35% | 5.35% | 5.35% | 6.63% | 5.35% |
| **False Negative Rate (FNR)** | 5.79% | 5.79% | 5.79% | 5.79% | 5.54% | 5.79% |
| **ROC-AUC** | 0.9819 | 0.9819 | 0.9819 | 0.9819 | 0.9819 | 0.9819 |
| **PR-AUC** | 0.9636 | 0.9636 | 0.9636 | 0.9636 | 0.9636 | 0.9636 |
| **False Positives (FP)** | 75 | 75 | 75 | 75 | 93 | 75 |
| **False Negatives (FN)** | 23 | 23 | 23 | 23 | 22 | 23 |
| **Sparse Legit FPR** | 28.89% | 28.89% | 28.89% | 28.89% | 34.22% | 28.89% |
| **Sparse Phishing Recall** | 98.97% | 98.97% | 98.97% | 98.97% | 98.97% | 98.97% |
| **HTTPS Phishing Recall** | 93.04% | 93.04% | 93.04% | 93.04% | 93.35% | 93.04% |
| **HTTPS Legit FPR** | 5.36% | 5.36% | 5.36% | 5.36% | 6.65% | 5.36% |
| **Zero Internal Links Legit FPR** | 29.91% | 29.91% | 29.91% | 29.91% | 33.64% | 29.91% |
| **Zero Internal Links Phish Recall** | 98.76% | 98.76% | 98.76% | 98.76% | 99.17% | 98.76% |
| **Legit Login/SSO FPR** | 3.17% | 3.17% | 3.17% | 3.17% | 4.52% | 3.17% |
| **Ext Form Legit FPR** | 2.30% | 2.30% | 2.30% | 2.30% | 2.30% | 2.30% |
| **Ext Form Phish Recall** | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| **Render Trigger Count** | 0 | 62 | 58 | 44 | 58 | 28 |
| **Render Trigger Rate** | 0.00% | 3.45% | 3.22% | 2.45% | 3.22% | 1.56% |
