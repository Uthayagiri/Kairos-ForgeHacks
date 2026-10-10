# Repeated 5-Seed Validation: Dynamic Content Feature Fusion
**Task ID**: `EXP-14-DYNAMIC-CONTENT-FEATURE-FUSION-2026-09-16`  
**Seeds Tested**: `[42, 101, 777, 2024, 9999]` (GroupShuffleSplit 80/20 grouped by apex domain)  

## Aggregate Stability & Generalization Metrics

| Candidate | Mean Phishing Recall | Recall Std | Worst-Seed Recall | Mean Overall FPR | Mean Sparse Legit FPR | Mean Precision | Total FNs (5 seeds) | Total FPs (5 seeds) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **CANDIDATE_A** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 84.54% | 192 | 336 |
| **CANDIDATE_C** | **90.61%** | ±6.65% | **77.32%** | 4.52% | 27.65% | 84.95% | 227 | 322 |
| **CANDIDATE_D** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 84.54% | 192 | 336 |
| **CANDIDATE_E** | **94.91%** | ±1.09% | **92.96%** | 5.78% | 32.59% | 82.14% | 112 | 412 |
