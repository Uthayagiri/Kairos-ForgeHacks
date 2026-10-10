import json
import numpy as np

with open("scratch/hard_negative_fp_reduction.json", "r", encoding="utf-8") as f:
    data = json.load(f)

print("=" * 80)
print("FIXED SPLIT (N=1,799, Seed 42) COMPARISON")
print("=" * 80)
fixed = data["fixed_split_comparison_n1799"]
for k, v in fixed.items():
    if "grid_search" in v:
        metrics = v["metrics"]
    else:
        metrics = v
    print(f"[{k}]")
    print(f"  Accuracy: {metrics['accuracy']*100:.2f}% | Recall: {metrics['recall']*100:.2f}% | Precision: {metrics['precision']*100:.2f}%")
    print(f"  F1: {metrics['f1_score']*100:.2f}% | Specificity: {metrics['specificity']*100:.2f}% | FPR: {metrics['false_positive_rate']*100:.2f}% | FNR: {metrics['false_negative_rate']*100:.2f}%")
    print(f"  ROC-AUC: {metrics['roc_auc']:.4f} | PR-AUC: {metrics['pr_auc']:.4f} | FP: {metrics['confusion_matrix']['fp']} | FN: {metrics['confusion_matrix']['fn']}")
    print(f"  Sparse Legit FPR: {metrics['slices']['sparse_legitimate_fpr']*100:.2f}% ({metrics['slices']['sparse_legitimate_fps']}/{metrics['slices']['sparse_legitimate_total']})")
    print(f"  Sparse Phish Recall: {metrics['slices']['sparse_phishing_recall']*100:.2f}% ({metrics['slices']['sparse_phishing_tps']}/{metrics['slices']['sparse_phishing_total']})")
    print(f"  HTTPS Phish Recall: {metrics['slices']['https_phishing_recall']*100:.2f}% | Shortened Phish Recall: {metrics['slices']['shortened_phishing_recall']*100:.2f}%")
    print(f"  Login Legit FPR: {metrics['slices']['legitimate_login_fpr']*100:.2f}% | ExtForm Legit FPR: {metrics['slices']['external_form_legitimate_fpr']*100:.2f}% | ExtForm Phish Recall: {metrics['slices']['external_form_phishing_recall']*100:.2f}%")
    print()

print("=" * 80)
print("THRESHOLD SWEEPS ON FIXED SPLIT (N=1,799)")
print("=" * 80)
sweeps = data["threshold_sweeps"]
for model_name, t_dict in sweeps.items():
    print(f"--- {model_name} ---")
    print(f"{'Threshold':<10} | {'Recall':<10} | {'FPR':<10} | {'Precision':<10} | {'F1':<10} | {'Sparse Legit FPR':<18} | {'FP':<5} | {'FN':<5}")
    for t_key, t_val in t_dict.items():
        t = t_val["threshold"]
        rec = t_val["recall"] * 100
        fpr = t_val["false_positive_rate"] * 100
        prec = t_val["precision"] * 100
        f1 = t_val["f1_score"] * 100
        sparse_fpr = t_val["slices"]["sparse_legitimate_fpr"] * 100
        fp = t_val["confusion_matrix"]["fp"]
        fn = t_val["confusion_matrix"]["fn"]
        print(f"{t:<10.2f} | {rec:<10.2f}% | {fpr:<10.2f}% | {prec:<10.2f}% | {f1:<10.2f}% | {sparse_fpr:<18.2f}% | {fp:<5} | {fn:<5}")
    print()

print("=" * 80)
print("5-SEED REPEATED VALIDATION (SEEDS: 42, 101, 777, 2024, 9999)")
print("=" * 80)
multi = data["multi_seed_results"] if "multi_seed_results" in data else data["multi_seed_validation_results"]

for cand in ["candidate_a", "candidate_b", "candidate_c", "candidate_d"]:
    recs = [m[cand]["recall"] * 100 for m in multi]
    accs = [m[cand]["accuracy"] * 100 for m in multi]
    precs = [m[cand]["precision"] * 100 for m in multi]
    f1s = [m[cand]["f1_score"] * 100 for m in multi]
    fprs = [m[cand]["false_positive_rate"] * 100 for m in multi]
    sparse_fprs = [m[cand]["slices"]["sparse_legitimate_fpr"] * 100 for m in multi]
    fns = [m[cand]["confusion_matrix"]["fn"] for m in multi]
    fps = [m[cand]["confusion_matrix"]["fp"] for m in multi]
    
    print(f"[{cand.upper()}]")
    print(f"  Recall (5 seeds):    {[round(x, 2) for x in recs]} -> Mean: {np.mean(recs):.2f}% +/- {np.std(recs):.2f}%")
    print(f"  FPR (5 seeds):       {[round(x, 2) for x in fprs]} -> Mean: {np.mean(fprs):.2f}% +/- {np.std(fprs):.2f}%")
    print(f"  Sparse FPR (5 seeds):{[round(x, 2) for x in sparse_fprs]} -> Mean: {np.mean(sparse_fprs):.2f}% +/- {np.std(sparse_fprs):.2f}%")
    print(f"  Precision (5 seeds): {[round(x, 2) for x in precs]} -> Mean: {np.mean(precs):.2f}% +/- {np.std(precs):.2f}%")
    print(f"  Accuracy (5 seeds):  {[round(x, 2) for x in accs]} -> Mean: {np.mean(accs):.2f}% +/- {np.std(accs):.2f}%")
    print(f"  F1 (5 seeds):        {[round(x, 2) for x in f1s]} -> Mean: {np.mean(f1s):.2f}% +/- {np.std(f1s):.2f}%")
    print(f"  FNs: {fns} (Sum: {sum(fns)}) | FPs: {fps} (Sum: {sum(fps)})")
    print()
