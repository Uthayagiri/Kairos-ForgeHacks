# Error Analysis: Selective Rendering & Threshold Tuning
**Task ID**: `EXP-15-SELECTIVE-RENDERING-THRESHOLD-TUNING-2026-09-16`  

## 1. False Positive Reduction Mechanism
Under Trigger T3, selective rendering evaluates only ambiguous pages ($0.35 \le S_1 \le 0.70$) that are sparse and contain JavaScript bundles.
When rendered, legitimate SPAs expand from 0 links to 15-40 navigation links.
Because these pages have zero strong phishing flags (no external form actions, no hidden iframes, no IP hostname), the presence of populated internal links confirms legitimate page architecture.

## 2. Phishing Recall Protection
Minimalist phishing lures with suspicious URL tokens or redirects trigger the strong phishing evidence veto and remain classified as threats, preventing new false negatives.
