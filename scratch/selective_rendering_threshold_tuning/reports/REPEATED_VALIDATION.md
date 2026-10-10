# Repeated 5-Seed Validation: Selective Rendering & Threshold Tuning
**Task ID**: `EXP-15-SELECTIVE-RENDERING-THRESHOLD-TUNING-2026-09-16`  
**Seeds Tested**: `[42, 101, 777, 2024, 9999]` (GroupShuffleSplit 80/20 grouped by apex domain)  

## Aggregate Stability & Generalization Metrics

| Candidate | Mean Phishing Recall | Recall Std | Worst-Seed Recall | Mean Overall FPR | Mean Sparse Legit FPR | Mean Precision | Total FNs (5 seeds) | Total FPs (5 seeds) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **CANDIDATE_A** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 84.54% | 192 | 336 |
| **CANDIDATE_D** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 84.54% | 192 | 336 |
| **CANDIDATE_F** | **94.91%** | ±1.14% | **92.96%** | 5.84% | 33.07% | 82.02% | 112 | 416 |
| **CANDIDATE_G** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 84.54% | 192 | 336 |
