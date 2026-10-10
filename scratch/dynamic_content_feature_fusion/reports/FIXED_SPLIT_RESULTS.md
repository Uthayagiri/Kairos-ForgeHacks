# Fixed-Split Results: Dynamic Content Feature Fusion
**Task ID**: `EXP-14-DYNAMIC-CONTENT-FEATURE-FUSION-2026-09-16`  
**Test Partition**: $N=1,799$ samples ($1,402$ Legitimate, $397$ Phishing across $631$ domain-disjoint apex domains)  

## Fixed Split Comparison Table ($N=1,799$, Seed 42)

| Metric | Candidate A (Baseline) | Candidate B (Rendered Schema) | Candidate C (Static + Delta) | Candidate D (Cons. Fusion) | Candidate E (Render Cascade) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Accuracy** | 94.55% | 94.55% | 94.83% | 94.55% | 93.72% |
| **Phishing Recall (>=94% req.)** | 94.21% | 94.21% | 93.95% | 94.21% | 94.71% |
| **Precision** | 83.30% | 83.30% | 84.39% | 83.30% | 80.34% |
| **F1-Score** | 88.42% | 88.42% | 88.92% | 88.42% | 86.94% |
| **Specificity** | 94.65% | 94.65% | 95.08% | 94.65% | 93.44% |
| **False Positive Rate (FPR)** | 5.35% | 5.35% | 4.92% | 5.35% | 6.56% |
| **False Negative Rate (FNR)** | 5.79% | 5.79% | 6.05% | 5.79% | 5.29% |
| **ROC-AUC** | 0.9819 | 0.9819 | 0.9818 | 0.9819 | 0.9821 |
| **PR-AUC** | 0.9636 | 0.9636 | 0.9629 | 0.9636 | 0.9639 |
| **False Positives (FP)** | 75 | 75 | 69 | 75 | 92 |
| **False Negatives (FN)** | 23 | 23 | 24 | 23 | 21 |
| **Sparse Legit FPR** | 28.89% | 28.89% | 27.11% | 28.89% | 33.78% |
| **Sparse Phishing Recall** | 98.97% | 98.97% | 98.62% | 98.97% | 98.97% |
| **HTTPS Phishing Recall** | 93.04% | 93.04% | 92.72% | 93.04% | 93.67% |
| **HTTPS Legit FPR** | 5.36% | 5.36% | 4.94% | 5.36% | 6.58% |
| **Zero Internal Links Legit FPR** | 29.91% | 29.91% | 28.04% | 29.91% | 33.64% |
| **Zero Internal Links Phish Recall** | 98.76% | 98.76% | 98.76% | 98.76% | 99.17% |
| **Legit Login/SSO FPR** | 3.17% | 3.17% | 3.17% | 3.17% | 4.52% |
| **Ext Form Legit FPR** | 2.30% | 2.30% | 2.30% | 2.30% | 2.30% |
| **Ext Form Phish Recall** | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| **JS-Rendered Legit FPR** | 4.12% | 4.12% | 3.67% | 4.12% | 5.47% |
| **Gov/Institutional Legit FPR** | 9.26% | 9.26% | 5.56% | 9.26% | 10.19% |
| **Cloud-Hosted Legit FPR** | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| **Long URL Phish Recall** | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| **Short URL Phish Recall** | 89.21% | 89.21% | 89.93% | 89.21% | 90.65% |
| **Redirect Page Recall** | 50.00% | 50.00% | 50.00% | 50.00% | 50.00% |
