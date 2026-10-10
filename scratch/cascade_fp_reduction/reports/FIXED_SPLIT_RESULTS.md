# Fixed-Split Cascade Benchmark Results
**Task ID**: `EXP-13-HIGH-RECALL-CASCADE-FP-REDUCTION-IMPLEMENTATION`  
**Date**: `2026-09-16`  
**Test Partition**: $N=1,799$ samples ($1,402$ Legitimate, $397$ Phishing across $631$ domain-disjoint apex domains)  

## 1. Candidate Architectural Configurations
- **Candidate A**: Production Stage 1 Only (Baseline, $\tau = 0.50$).
- **Candidate B**: Production Stage 1 + Stage 2 Verifier on all $S_1 \ge 0.50$ (No Veto).
- **Candidate C**: Production Stage 1 + Stage 2 Verifier on Borderline Scores ($0.35 \le S_1 \le 0.70$).
- **Candidate D**: Production Stage 1 + Borderline Stage 2 + Strict Multi-Indicator Phishing Veto.
- **Candidate E**: Conservative Risk-Banding Cascade (High/Medium/Low with SPA context de-escalation).

## 2. Benchmark Metric Table ($N=1,799$, Seed 42)

| Metric | Candidate A (Baseline) | Candidate B (No Veto) | Candidate C (Borderline) | Candidate D (Strict Veto) | Candidate E (Risk Banding) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Accuracy** | 94.55% | 95.16% | 94.89% | 93.77% | 37.52% |
| **Phishing Recall (>=94% req.)** | 94.21% | 90.93% | 91.94% | 93.45% | 96.47% |
| **Precision** | 83.30% | 87.62% | 85.88% | 81.18% | 25.65% |
| **F1-Score** | 88.42% | 89.25% | 88.81% | 86.89% | 40.53% |
| **Specificity** | 94.65% | 96.36% | 95.72% | 93.87% | 20.83% |
| **False Positive Rate (FPR)** | 5.35% | 3.64% | 4.28% | 6.13% | 79.17% |
| **False Negative Rate (FNR)** | 5.79% | 9.07% | 8.06% | 6.55% | 3.53% |
| **ROC-AUC** | 0.9819 | 0.9769 | 0.9814 | 0.9816 | 0.9816 |
| **PR-AUC** | 0.9636 | 0.9410 | 0.9623 | 0.9627 | 0.9627 |
| **False Positives (FP)** | 75 | 51 | 60 | 86 | 1110 |
| **False Negatives (FN)** | 23 | 36 | 32 | 26 | 14 |
| **Sparse Legit FPR** | 28.89% | 19.11% | 21.33% | 31.11% | 61.78% |
| **Sparse Phishing Recall** | 98.97% | 96.21% | 97.24% | 98.62% | 98.62% |
| **HTTPS Phishing Recall** | 93.04% | 88.92% | 90.19% | 92.09% | 95.89% |
| **HTTPS Legit FPR** | 5.36% | 3.65% | 4.29% | 6.15% | 79.18% |
| **Zero Internal Links Phish Recall** | 98.76% | 98.34% | 98.76% | 99.17% | 99.17% |
| **Zero Internal Links Legit FPR** | 29.91% | 16.82% | 19.63% | 28.97% | 61.68% |
| **Legit Login/SSO FPR** | 3.17% | 2.71% | 3.17% | 4.52% | 92.31% |
| **External Form Legit FPR** | 2.30% | 2.30% | 2.30% | 2.30% | 100.00% |
| **External Form Phish Recall** | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| **JS-Rendered Legit FPR** | 4.12% | 2.77% | 3.45% | 5.32% | 81.33% |
| **Gov/Institutional Legit FPR** | 9.26% | 4.63% | 4.63% | 9.26% | 85.19% |
| **Cloud-Hosted Legit FPR** | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% |
| **Long URL Phish Recall** | 100.00% | 98.46% | 100.00% | 100.00% | 100.00% |
| **Short URL Phish Recall** | 89.21% | 82.01% | 83.45% | 87.05% | 92.81% |
| **Redirect Page Recall** | 50.00% | 50.00% | 50.00% | 50.00% | 100.00% |
