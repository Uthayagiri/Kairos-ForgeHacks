# Cascade Architecture Error Analysis Report
**Task ID**: `EXP-13-HIGH-RECALL-CASCADE-FP-REDUCTION-IMPLEMENTATION`  
**Date**: `2026-09-16`  

## 1. Executive Error Analysis Summary
- **Baseline False Positives (Candidate A)**: 75 FP
- **Candidate B False Positives**: 51 FP (Reduced by **24**)
- **Baseline False Negatives (Candidate A)**: 23 FN
- **Candidate B False Negatives**: 36 FN (Increased by **+13** new false negatives)

## 2. Deep Dive: Why False Positives Were Successfully Reduced
Stage 2 evaluated genuine legitimate single-page applications (SPAs) and sparse institutional portals that Stage 1 misclassified due to `num_internal_links == 0`.
Because these samples lacked explicit phishing flags (no external form posting, no hidden iframes, no brand mismatch, no URL encoding), Stage 2 computed low threat scores ($S_2 < 0.50$), successfully de-escalating them.

### Sample Reduced False Positives:
| URL | Domain | Stage 1 Score | Stage 2 Score | Num Links | De-escalation Rationale |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `https://fastly.net/signup...` | `fastly.net` | 0.6702 | 0.4352 | 0 | Low Stage 2 threat score due to lack of obfuscation / phishing flags despite low link count |
| `https://store.office.com/worldwide.aspx?rs=en-us&return...` | `office.com` | 0.5882 | 0.4426 | 187 | Low Stage 2 threat score due to lack of obfuscation / phishing flags despite low link count |
| `https://app.vungle.com/login/...` | `vungle.com` | 0.5343 | 0.3302 | 0 | Low Stage 2 threat score due to lack of obfuscation / phishing flags despite low link count |
| `https://target.com/b/threshold/-/N-56dig...` | `target.com` | 0.6433 | 0.3230 | 19 | Low Stage 2 threat score due to lack of obfuscation / phishing flags despite low link count |
| `https://www.livejournal.com/identity/login.bml?type=vko...` | `livejournal.com` | 0.7799 | 0.3604 | 0 | Low Stage 2 threat score due to lack of obfuscation / phishing flags despite low link count |

## 3. Deep Dive: Why New False Negatives Were Created
The primary failure mode of unconstrained Stage 2 (Candidate B and Candidate C) is that **minimalist phishing lures** that omit static `<form>` tags and contain few links fool Stage 2 into classifying them as benign SPAs.
On Seed 2024, Candidate B missed $193$ attacks (Recall = $66.84\%$).

### Sample New False Negatives (Attacks Missed by Stage 2):
| URL | Domain | Stage 1 Score | Stage 2 Score | Has Veto? | Miss Rationale |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `https://t.co/HAdLWI1t8j...` | `t.co` | 0.6198 | 0.2435 | No | Minimalist phishing attack without static forms or suspicious keywords; Stage 2 mistook sparsity for legitimate SPA |
| `https://www.secureaccountview.com/BFWeb/clients/credits...` | `secureaccountview.com` | 0.6794 | 0.4891 | Yes | Minimalist phishing attack without static forms or suspicious keywords; Stage 2 mistook sparsity for legitimate SPA |
| `https://l.ead.me/bgx38x...` | `ead.me` | 0.8283 | 0.4634 | Yes | Minimalist phishing attack without static forms or suspicious keywords; Stage 2 mistook sparsity for legitimate SPA |
| `https://t.co/PmzMVWM4y8...` | `t.co` | 0.6198 | 0.2435 | No | Minimalist phishing attack without static forms or suspicious keywords; Stage 2 mistook sparsity for legitimate SPA |
| `https://l.ead.me/bgwq6Y...` | `ead.me` | 0.6917 | 0.3860 | Yes | Minimalist phishing attack without static forms or suspicious keywords; Stage 2 mistook sparsity for legitimate SPA |
