# Runtime Analysis: Selective Headless Rendering
**Task ID**: `EXP-15-SELECTIVE-RENDERING-THRESHOLD-TUNING-2026-09-16`  

## 1. Latency & Trigger Breakdown
- **Static Feature Extraction (Mean)**: `1.25 ms`
- **Headless Rendering Latency (Mean)**: `2015.26 ms`
- **Headless Rendering Latency (p50)**: `2002.10 ms`
- **Headless Rendering Latency (p95)**: `2045.50 ms`
- **Trigger Rate (Trigger T3)**: `3.22% (58 / 1799)`
- **Effective Pipeline Latency (Weighted Mean)**: `66.14 ms`

## 2. Operational Feasibility
Selective rendering bounds the 2,000ms headless browser latency to only **~5% - 8% of total traffic** (ambiguous sparse pages in the borderline score band).
Over 92% of queries complete in under 2ms via static extraction, preserving real-time browser extension responsiveness.
