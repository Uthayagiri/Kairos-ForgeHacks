# Repeated 5-Seed Cascade Domain-Disjoint Validation Report
**Task ID**: `EXP-13-HIGH-RECALL-CASCADE-FP-REDUCTION-IMPLEMENTATION`  
**Date**: `2026-09-16`  
**Seeds Tested**: `[42, 101, 777, 2024, 9999]` (GroupShuffleSplit 80/20 grouped by apex domain)  

## 1. Aggregate Stability & Generalization Metrics

| Candidate | Mean Phishing Recall | Recall Std | Worst-Seed Recall | Mean Overall FPR | Mean Sparse Legit FPR | Mean Precision | Total FNs (5 seeds) | Total FPs (5 seeds) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **CANDIDATE_A** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 84.54% | 192 | 336 |
| **CANDIDATE_B** | **86.45%** | ±9.87% | **66.84%** | 3.20% | 18.75% | 88.40% | 324 | 228 |
| **CANDIDATE_C** | **88.84%** | ±9.69% | **69.59%** | 3.84% | 21.34% | 86.74% | 274 | 273 |
| **CANDIDATE_D** | **94.32%** | ±1.05% | **93.13%** | 5.40% | 29.94% | 83.13% | 122 | 385 |
| **CANDIDATE_E** | **98.11%** | ±0.94% | **96.73%** | 82.24% | 67.55% | 26.13% | 40 | 5867 |

## 2. Per-Seed Phishing Recall & FPR Breakdown

| Seed | Candidate A (Base) | Candidate B (No Veto) | Candidate C (Borderline) | Candidate D (Strict Veto) | Candidate E (Cons. Cascade) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **Seed 42** | Rec: 94.21%, FPR: 5.35% | Rec: 90.93%, FPR: 3.64% | Rec: 91.94%, FPR: 4.28% | Rec: 93.45%, FPR: 6.13% | Rec: 96.73%, FPR: 79.32% |
| **Seed 101** | Rec: 93.98%, FPR: 5.56% | Rec: 92.47%, FPR: 3.80% | Rec: 94.84%, FPR: 4.43% | Rec: 95.48%, FPR: 6.26% | Rec: 98.92%, FPR: 83.54% |
| **Seed 777** | Rec: 93.47%, FPR: 5.09% | Rec: 89.39%, FPR: 3.07% | Rec: 93.06%, FPR: 3.77% | Rec: 93.88%, FPR: 5.30% | Rec: 97.96%, FPR: 83.46% |
| **Seed 2024** | Rec: 82.82%, FPR: 4.44% | Rec: 66.84%, FPR: 3.38% | Rec: 69.59%, FPR: 3.88% | Rec: 93.13%, FPR: 5.21% | Rec: 97.59%, FPR: 80.55% |
| **Seed 9999** | Rec: 94.58%, FPR: 3.16% | Rec: 92.62%, FPR: 2.13% | Rec: 94.79%, FPR: 2.82% | Rec: 95.66%, FPR: 4.12% | Rec: 99.35%, FPR: 84.34% |
