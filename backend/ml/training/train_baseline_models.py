"""Baseline Model Training & Evaluation Module.

Trains, evaluates, and rigorously compares Random Forest and XGBoost baseline classifiers
on the combined URL and HTML training dataset.
"""

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Paths
BACKEND_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_PATH = BACKEND_ROOT / "data" / "processed" / "training_dataset.csv"
DEFAULT_REPORT_PATH = BACKEND_ROOT / "data" / "processed" / "model_comparison_report.json"

IDENTIFIER_COLUMNS = ["url", "label", "label_binary"]


def load_and_split_dataset(
    dataset_path: Path = DEFAULT_DATASET_PATH,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, List[str]]:
    """Load the processed training dataset and split into stratified train and test sets.

    Args:
        dataset_path: Path to training_dataset.csv.
        test_size: Proportion of the dataset to reserve for held-out test evaluation.
        random_state: Random seed for reproducibility.

    Returns:
        Tuple of (X_train, X_test, y_train, y_test, feature_names).
    """
    if not dataset_path.exists():
        raise FileNotFoundError(f"Training dataset not found: {dataset_path}")

    logger.info("Loading training dataset from %s...", dataset_path)
    df = pd.read_csv(dataset_path)

    if "label_binary" not in df.columns:
        raise ValueError("Missing 'label_binary' target column in dataset.")

    y = df["label_binary"].astype(int)
    drop_cols = [c for c in IDENTIFIER_COLUMNS if c in df.columns]
    X = df.drop(columns=drop_cols)
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        stratify=y,
        random_state=random_state,
    )

    logger.info(
        "Dataset loaded successfully: %d total samples | 43 features\n"
        "  - Train Set: %d samples (Legit: %d, Phish: %d)\n"
        "  - Test Set:  %d samples (Legit: %d, Phish: %d)",
        len(df),
        len(X_train),
        int((y_train == 0).sum()),
        int((y_train == 1).sum()),
        len(X_test),
        int((y_test == 0).sum()),
        int((y_test == 1).sum()),
    )

    return X_train, X_test, y_train, y_test, feature_names


def evaluate_predictions(
    y_true: Union[pd.Series, np.ndarray, List[int]],
    y_pred: Union[pd.Series, np.ndarray, List[int]],
    y_prob: Optional[Union[pd.Series, np.ndarray, List[float]]] = None,
) -> Dict[str, Any]:
    """Compute comprehensive classification performance metrics.

    Args:
        y_true: Ground truth binary labels (0 = legitimate, 1 = phishing).
        y_pred: Predicted binary labels (0 or 1).
        y_prob: Predicted probabilities for the positive class (phishing / 1).

    Returns:
        Dictionary containing accuracy, precision, recall, f1, roc_auc, and confusion matrix breakdown.
    """
    y_true_arr = np.asarray(y_true, dtype=int)
    y_pred_arr = np.asarray(y_pred, dtype=int)

    acc = float(accuracy_score(y_true_arr, y_pred_arr))
    prec = float(precision_score(y_true_arr, y_pred_arr, pos_label=1, zero_division=0))
    rec = float(recall_score(y_true_arr, y_pred_arr, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_true_arr, y_pred_arr, pos_label=1, zero_division=0))

    roc_auc = None
    if y_prob is not None:
        y_prob_arr = np.asarray(y_prob, dtype=float)
        # Verify both classes exist before computing ROC-AUC
        if len(np.unique(y_true_arr)) > 1:
            roc_auc = float(roc_auc_score(y_true_arr, y_prob_arr))

    cm = confusion_matrix(y_true_arr, y_pred_arr)
    # Extract TN, FP, FN, TP safely
    if cm.shape == (2, 2):
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    else:
        tn = int(cm[0, 0]) if len(y_true_arr) > 0 else 0
        fp, fn, tp = 0, 0, 0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "confusion_matrix": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
    }


def perform_cross_validation(
    model_factory: Callable[[], Any],
    X_train: pd.DataFrame,
    y_train: pd.Series,
    n_splits: int = 5,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Execute stratified k-fold cross-validation on the training set.

    Args:
        model_factory: Callable returning a fresh unfitted model instance.
        X_train: Training features DataFrame.
        y_train: Training target Series.
        n_splits: Number of cross-validation folds.
        random_state: Random seed for fold partitioning.

    Returns:
        Dictionary containing fold metrics, means, and standard deviations.
    """
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    fold_accuracies: List[float] = []
    fold_f1_scores: List[float] = []

    X_train_reset = X_train.reset_index(drop=True)
    y_train_reset = y_train.reset_index(drop=True)

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X_train_reset, y_train_reset), 1):
        fold_X_tr, fold_y_tr = X_train_reset.iloc[train_idx], y_train_reset.iloc[train_idx]
        fold_X_val, fold_y_val = X_train_reset.iloc[val_idx], y_train_reset.iloc[val_idx]

        fold_model = model_factory()
        fold_model.fit(fold_X_tr, fold_y_tr)
        fold_y_pred = fold_model.predict(fold_X_val)

        acc = float(accuracy_score(fold_y_val, fold_y_pred))
        f1 = float(f1_score(fold_y_val, fold_y_pred, pos_label=1, zero_division=0))

        fold_accuracies.append(round(acc, 4))
        fold_f1_scores.append(round(f1, 4))

    return {
        "folds": n_splits,
        "cv_accuracy_mean": round(float(np.mean(fold_accuracies)), 4),
        "cv_accuracy_std": round(float(np.std(fold_accuracies)), 4),
        "cv_f1_mean": round(float(np.mean(fold_f1_scores)), 4),
        "cv_f1_std": round(float(np.std(fold_f1_scores)), 4),
        "fold_accuracies": fold_accuracies,
        "fold_f1_scores": fold_f1_scores,
    }


def extract_feature_importances(
    model: Any,
    feature_names: List[str],
    top_n: int = 15,
) -> List[Dict[str, Any]]:
    """Extract and rank the top N most important features from a fitted tree-based model.

    Args:
        model: Fitted model instance supporting .feature_importances_.
        feature_names: List of feature column names.
        top_n: Number of top features to return.

    Returns:
        List of dictionaries with 'feature' and 'importance' keys, sorted descending.
    """
    if not hasattr(model, "feature_importances_"):
        raise AttributeError("Model does not expose 'feature_importances_'.")

    importances = model.feature_importances_
    ranked = sorted(
        zip(feature_names, importances),
        key=lambda item: float(item[1]),
        reverse=True,
    )

    top_features = [
        {"feature": name, "importance": round(float(score), 6)}
        for name, score in ranked[:top_n]
    ]
    return top_features


def train_and_evaluate_baselines(
    dataset_path: Path = DEFAULT_DATASET_PATH,
    output_report_path: Path = DEFAULT_REPORT_PATH,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Train, cross-validate, evaluate, and compare baseline Random Forest and XGBoost models.

    Args:
        dataset_path: Path to input training dataset CSV.
        output_report_path: Path to output JSON comparison report.
        random_state: Random seed for split and model reproducibility.

    Returns:
        Comprehensive comparison dictionary.
    """
    X_train, X_test, y_train, y_test, feature_names = load_and_split_dataset(
        dataset_path=dataset_path,
        test_size=0.2,
        random_state=random_state,
    )

    # Define baseline model factories
    model_factories = {
        "random_forest": {
            "name": "Random Forest",
            "factory": lambda: RandomForestClassifier(
                n_estimators=100,
                random_state=random_state,
            ),
            "params": {"n_estimators": 100, "random_state": random_state},
        },
        "xgboost": {
            "name": "XGBoost",
            "factory": lambda: XGBClassifier(
                eval_metric="logloss",
                random_state=random_state,
            ),
            "params": {"eval_metric": "logloss", "random_state": random_state},
        },
    }

    report: Dict[str, Any] = {
        "dataset_metadata": {
            "total_samples": len(X_train) + len(X_test),
            "num_features": len(feature_names),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "legitimate_train_count": int((y_train == 0).sum()),
            "phishing_train_count": int((y_train == 1).sum()),
            "legitimate_test_count": int((y_test == 0).sum()),
            "phishing_test_count": int((y_test == 1).sum()),
            "random_state": random_state,
        },
        "models": {},
    }

    fitted_models: Dict[str, Any] = {}

    for model_key, spec in model_factories.items():
        model_name = spec["name"]
        logger.info("Executing 5-fold Cross-Validation for %s on training set...", model_name)
        cv_results = perform_cross_validation(
            model_factory=spec["factory"],
            X_train=X_train,
            y_train=y_train,
            n_splits=5,
            random_state=random_state,
        )

        logger.info("Training full %s model on (X_train, y_train)...", model_name)
        model = spec["factory"]()
        model.fit(X_train, y_train)
        fitted_models[model_key] = model

        # Predict on held-out test set
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

        test_eval = evaluate_predictions(y_test, y_pred, y_prob)
        top_15 = extract_feature_importances(model, feature_names, top_n=15)

        report["models"][model_key] = {
            "name": model_name,
            "parameters": spec["params"],
            "test_metrics": {
                "accuracy": test_eval["accuracy"],
                "precision": test_eval["precision"],
                "recall": test_eval["recall"],
                "f1": test_eval["f1"],
                "roc_auc": test_eval["roc_auc"],
            },
            "confusion_matrix": test_eval["confusion_matrix"],
            "cross_validation_train": cv_results,
            "top_15_features": top_15,
        }

    # Persist report JSON
    output_report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_report_path, mode="w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info("Model comparison report saved to %s", output_report_path)

    # -------------------------------------------------------------
    # Formatted Console Summary
    # -------------------------------------------------------------
    rf = report["models"]["random_forest"]
    xgb = report["models"]["xgboost"]

    print("\n" + "=" * 80)
    print("           STAGE 6: BASELINE MODEL COMPARISON & EVALUATION")
    print("=" * 80)
    print(f"Dataset Size: {report['dataset_metadata']['total_samples']} samples | Train: {report['dataset_metadata']['train_samples']} | Test: {report['dataset_metadata']['test_samples']}")
    print("-" * 80)
    print(f"{'Metric / Evaluation':<32} {'Random Forest':<22} {'XGBoost':<22}")
    print("-" * 80)
    print(f"{'Test Accuracy':<32} {rf['test_metrics']['accuracy']:<22.4f} {xgb['test_metrics']['accuracy']:<22.4f}")
    print(f"{'Test Precision (Phishing)':<32} {rf['test_metrics']['precision']:<22.4f} {xgb['test_metrics']['precision']:<22.4f}")
    print(f"{'Test Recall (Phishing)':<32} {rf['test_metrics']['recall']:<22.4f} {xgb['test_metrics']['recall']:<22.4f}")
    print(f"{'Test F1-Score':<32} {rf['test_metrics']['f1']:<22.4f} {xgb['test_metrics']['f1']:<22.4f}")
    print(f"{'Test ROC-AUC':<32} {rf['test_metrics']['roc_auc']:<22.4f} {xgb['test_metrics']['roc_auc']:<22.4f}")
    print("-" * 80)
    print(f"{'5-Fold CV Accuracy (Mean+/-Std)':<32} {rf['cross_validation_train']['cv_accuracy_mean']:.4f} +/- {rf['cross_validation_train']['cv_accuracy_std']:.4f}     {xgb['cross_validation_train']['cv_accuracy_mean']:.4f} +/- {xgb['cross_validation_train']['cv_accuracy_std']:.4f}")
    print(f"{'5-Fold CV F1-Score (Mean+/-Std)':<32} {rf['cross_validation_train']['cv_f1_mean']:.4f} +/- {rf['cross_validation_train']['cv_f1_std']:.4f}     {xgb['cross_validation_train']['cv_f1_mean']:.4f} +/- {xgb['cross_validation_train']['cv_f1_std']:.4f}")
    print("-" * 80)
    print(f"CONFUSION MATRIX BREAKDOWN (Held-out Test Set, N={report['dataset_metadata']['test_samples']}):")
    print(f"  - True Negatives (TN - Legit as Legit):      RF = {rf['confusion_matrix']['tn']:<5} | XGB = {xgb['confusion_matrix']['tn']:<5}")
    print(f"  - False Positives (FP - Legit as Phish):     RF = {rf['confusion_matrix']['fp']:<5} | XGB = {xgb['confusion_matrix']['fp']:<5}")
    print(f"  - False Negatives (FN - Phish as Legit):     RF = {rf['confusion_matrix']['fn']:<5} | XGB = {xgb['confusion_matrix']['fn']:<5}")
    print(f"  - True Positives (TP - Phish as Phish):      RF = {rf['confusion_matrix']['tp']:<5} | XGB = {xgb['confusion_matrix']['tp']:<5}")
    print("-" * 80)
    print("TOP FEATURE IMPORTANCES (Random Forest vs. XGBoost):")
    print(f"{'Rank':<5} {'Random Forest Feature':<32} {'RF Score':<10} {'XGBoost Feature':<32} {'XGB Score':<10}")
    print("-" * 80)
    num_display = min(15, len(rf["top_15_features"]), len(xgb["top_15_features"]))
    for i in range(num_display):
        rf_feat = rf["top_15_features"][i]
        xgb_feat = xgb["top_15_features"][i]
        print(f"{i+1:<5} {rf_feat['feature']:<32} {rf_feat['importance']:<10.4f} {xgb_feat['feature']:<32} {xgb_feat['importance']:<10.4f}")
    print("=" * 80 + "\n")

    return report


if __name__ == "__main__":
    train_and_evaluate_baselines()
