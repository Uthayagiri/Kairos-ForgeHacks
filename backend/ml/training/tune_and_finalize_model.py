"""Stage 7: Hyperparameter Tuning, Model Selection, Model Persistence & Inference Pipeline.

Performs GridSearchCV with multi-metric tracking for Random Forest and XGBoost,
addresses class imbalance, evaluates both tuned models on the held-out test set,
selects the optimal model, persists production artifacts, and provides an inference round-trip utility.
"""

import datetime
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from xgboost import XGBClassifier

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from ml.training.train_baseline_models import (
    DEFAULT_DATASET_PATH,
    evaluate_predictions,
    extract_feature_importances,
    load_and_split_dataset,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = BACKEND_ROOT / "ml" / "models"
MODEL_FILE_PATH = MODELS_DIR / "phishing_model.joblib"
METADATA_FILE_PATH = MODELS_DIR / "model_metadata.json"
FEATURE_COLUMNS_FILE_PATH = MODELS_DIR / "feature_columns.json"


def compute_scale_pos_weight(y_train: Union[pd.Series, np.ndarray, List[int]]) -> float:
    """Compute the negative-to-positive class sample ratio for XGBoost scale_pos_weight.

    Args:
        y_train: Binary training labels (0 = legitimate, 1 = phishing).

    Returns:
        Float ratio of count(0) / count(1).
    """
    y_arr = np.asarray(y_train, dtype=int)
    num_neg = int((y_arr == 0).sum())
    num_pos = int((y_arr == 1).sum())
    if num_pos == 0:
        return 1.0
    return round(float(num_neg / num_pos), 4)


def extract_grid_search_summary(grid_search: GridSearchCV, top_n: int = 5) -> List[Dict[str, Any]]:
    """Extract a clean summary of candidates from GridSearchCV results sorted by mean test recall.

    Args:
        grid_search: Fitted GridSearchCV instance with multi-metric scoring.
        top_n: Number of top candidate configurations to return.

    Returns:
        List of candidate dictionaries with params and mean/std metrics for recall, f1, and precision.
    """
    results = grid_search.cv_results_
    num_candidates = len(results["params"])
    candidates = []

    for i in range(num_candidates):
        cand = {
            "rank_recall": int(results.get("rank_test_recall", [i + 1] * num_candidates)[i]),
            "params": results["params"][i],
            "cv_recall_mean": round(float(results["mean_test_recall"][i]), 4),
            "cv_recall_std": round(float(results["std_test_recall"][i]), 4),
            "cv_f1_mean": round(float(results.get("mean_test_f1", [0.0] * num_candidates)[i]), 4),
            "cv_f1_std": round(float(results.get("std_test_f1", [0.0] * num_candidates)[i]), 4),
            "cv_precision_mean": round(float(results.get("mean_test_precision", [0.0] * num_candidates)[i]), 4),
            "cv_precision_std": round(float(results.get("std_test_precision", [0.0] * num_candidates)[i]), 4),
        }
        candidates.append(cand)

    candidates.sort(key=lambda x: (x["cv_recall_mean"], x["cv_f1_mean"]), reverse=True)
    return candidates[:top_n]


def run_random_forest_grid_search(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    param_grid: Optional[Dict[str, List[Any]]] = None,
    cv_splits: int = 5,
    random_state: int = 42,
    n_jobs: int = -1,
) -> GridSearchCV:
    """Execute GridSearchCV for Random Forest optimizing recall with multi-metric tracking.

    Args:
        X_train: Training features DataFrame.
        y_train: Training target Series.
        param_grid: Optional custom grid.
        cv_splits: Number of cross-validation folds.
        random_state: Random seed.
        n_jobs: Number of parallel jobs.

    Returns:
        Fitted GridSearchCV object.
    """
    if param_grid is None:
        param_grid = {
            "n_estimators": [100, 200],
            "max_depth": [None, 20, 30],
            "min_samples_split": [2, 5],
            "class_weight": [None, "balanced"],
        }

    base_rf = RandomForestClassifier(random_state=random_state)
    cv = StratifiedKFold(n_splits=cv_splits, shuffle=True, random_state=random_state)
    scoring = {
        "recall": "recall",
        "f1": "f1",
        "precision": "precision",
    }

    grid_search = GridSearchCV(
        estimator=base_rf,
        param_grid=param_grid,
        scoring=scoring,
        refit="recall",
        cv=cv,
        n_jobs=n_jobs,
        verbose=0,
    )

    logger.info("Executing Random Forest GridSearchCV (%d parameter combinations)...", len(GridSearchCV(base_rf, param_grid).param_grid))
    grid_search.fit(X_train, y_train)
    return grid_search


def run_xgboost_grid_search(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    param_grid: Optional[Dict[str, List[Any]]] = None,
    cv_splits: int = 5,
    random_state: int = 42,
    n_jobs: int = -1,
) -> GridSearchCV:
    """Execute GridSearchCV for XGBoost optimizing recall with multi-metric tracking.

    Args:
        X_train: Training features DataFrame.
        y_train: Training target Series.
        param_grid: Optional custom grid.
        cv_splits: Number of cross-validation folds.
        random_state: Random seed.
        n_jobs: Number of parallel jobs.

    Returns:
        Fitted GridSearchCV object.
    """
    scale_pos_weight_val = compute_scale_pos_weight(y_train)

    if param_grid is None:
        param_grid = {
            "n_estimators": [100, 200],
            "max_depth": [4, 6, 8],
            "learning_rate": [0.05, 0.1, 0.2],
            "scale_pos_weight": [1.0, scale_pos_weight_val],
        }

    base_xgb = XGBClassifier(
        eval_metric="logloss",
        random_state=random_state,
    )
    cv = StratifiedKFold(n_splits=cv_splits, shuffle=True, random_state=random_state)
    scoring = {
        "recall": "recall",
        "f1": "f1",
        "precision": "precision",
    }

    grid_search = GridSearchCV(
        estimator=base_xgb,
        param_grid=param_grid,
        scoring=scoring,
        refit="recall",
        cv=cv,
        n_jobs=n_jobs,
        verbose=0,
    )

    logger.info("Executing XGBoost GridSearchCV (%d parameter combinations)...", len(GridSearchCV(base_xgb, param_grid).param_grid))
    grid_search.fit(X_train, y_train)
    return grid_search


def select_best_model(
    rf_eval: Dict[str, Any],
    xgb_eval: Dict[str, Any],
    rf_cv: Dict[str, Any],
    xgb_cv: Dict[str, Any],
    rf_best_params: Dict[str, Any],
    xgb_best_params: Dict[str, Any],
) -> Tuple[str, str]:
    """Select the winning model between tuned Random Forest and tuned XGBoost with detailed rationale.

    Args:
        rf_eval: Held-out test evaluation metrics for Random Forest.
        xgb_eval: Held-out test evaluation metrics for XGBoost.
        rf_cv: CV metrics summary for Random Forest.
        xgb_cv: CV metrics summary for XGBoost.
        rf_best_params: Winning params for Random Forest.
        xgb_best_params: Winning params for XGBoost.

    Returns:
        Tuple of (chosen_model_key, human_readable_justification).
    """
    rf_recall = rf_eval["recall"]
    xgb_recall = xgb_eval["recall"]
    rf_f1 = rf_eval["f1"]
    xgb_f1 = xgb_eval["f1"]
    rf_prec = rf_eval["precision"]
    xgb_prec = xgb_eval["precision"]
    rf_fp = rf_eval["confusion_matrix"]["fp"]
    xgb_fp = xgb_eval["confusion_matrix"]["fp"]
    rf_fn = rf_eval["confusion_matrix"]["fn"]
    xgb_fn = xgb_eval["confusion_matrix"]["fn"]

    # Decision logic: Primary = Recall, Guardrail = F1 / Precision without excessive False Positives
    if xgb_recall > rf_recall and xgb_f1 >= (rf_f1 - 0.02):
        winner = "xgboost"
        justification = (
            f"XGBoost selected as the final production model. It achieved superior held-out test recall "
            f"({xgb_recall:.4f} vs {rf_recall:.4f}, catching {xgb_eval['confusion_matrix']['tp']} / "
            f"{xgb_eval['confusion_matrix']['tp'] + xgb_fn} phishing attacks with only {xgb_fn} false negatives) "
            f"while maintaining high precision ({xgb_prec:.4f}) and F1-score ({xgb_f1:.4f}). "
            f"5-fold CV recall mean was {xgb_cv['cv_recall_mean']:.4f} (+/- {xgb_cv['cv_recall_std']:.4f})."
        )
    elif rf_recall > xgb_recall and rf_f1 >= (xgb_f1 - 0.02):
        winner = "random_forest"
        justification = (
            f"Random Forest selected as the final production model. It achieved higher held-out test recall "
            f"({rf_recall:.4f} vs {xgb_recall:.4f}) while maintaining solid precision ({rf_prec:.4f}) "
            f"and F1-score ({rf_f1:.4f}). 5-fold CV recall mean was {rf_cv['cv_recall_mean']:.4f}."
        )
    else:
        # If recall is tied, choose the model with higher F1 / lower false positives
        if xgb_f1 >= rf_f1:
            winner = "xgboost"
            justification = (
                f"XGBoost selected as the final production model. With test recall comparable ({xgb_recall:.4f} vs {rf_recall:.4f}), "
                f"XGBoost achieved higher F1 ({xgb_f1:.4f} vs {rf_f1:.4f}) and fewer false positives ({xgb_fp} vs {rf_fp}), "
                f"providing optimal defense against phishing attacks without disrupting legitimate browsing."
            )
        else:
            winner = "random_forest"
            justification = (
                f"Random Forest selected as the final production model. With test recall comparable ({rf_recall:.4f} vs {xgb_recall:.4f}), "
                f"Random Forest achieved higher F1 ({rf_f1:.4f} vs {xgb_f1:.4f}) and fewer false positives ({rf_fp} vs {xgb_fp})."
            )

    return winner, justification


def persist_model_artifacts(
    chosen_model: Any,
    chosen_model_name: str,
    chosen_params: Dict[str, Any],
    feature_names: List[str],
    test_metrics: Dict[str, Any],
    confusion_matrix_breakdown: Dict[str, int],
    cv_summary: Dict[str, Any],
    justification: str,
    dataset_metadata: Dict[str, Any],
    output_dir: Path = MODELS_DIR,
) -> Tuple[Path, Path, Path]:
    """Persist the trained model joblib, ordered feature columns JSON, and comprehensive metadata JSON.

    Args:
        chosen_model: Trained winning model instance.
        chosen_model_name: Name/key ('xgboost' or 'random_forest').
        chosen_params: Best hyperparameters dictionary.
        feature_names: Exact ordered list of feature column names.
        test_metrics: Evaluation metrics dictionary on test set.
        confusion_matrix_breakdown: TN, FP, FN, TP dictionary.
        cv_summary: 5-fold CV metric summary.
        justification: Text explaining model choice.
        dataset_metadata: Row counts, class balance, split parameters.
        output_dir: Target directory for persistence.

    Returns:
        Tuple of (model_file_path, feature_columns_path, metadata_file_path).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "phishing_model.joblib"
    feature_cols_path = output_dir / "feature_columns.json"
    metadata_path = output_dir / "model_metadata.json"

    # 1. Save Joblib Model
    joblib.dump(chosen_model, model_path)
    logger.info("Persisted final trained model to %s", model_path)

    # 2. Save Ordered Feature Columns JSON
    with open(feature_cols_path, mode="w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)
    logger.info("Persisted %d ordered feature columns to %s", len(feature_names), feature_cols_path)

    # Clean serializable params
    clean_params = {}
    for k, v in chosen_params.items():
        clean_params[k] = None if v is None else (v if isinstance(v, (int, float, str, bool, list)) else str(v))

    # 3. Save Model Metadata JSON
    metadata = {
        "model_type": chosen_model_name,
        "model_version": "1.0.0",
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dataset_info": {
            "source": "backend/data/processed/training_dataset.csv (post-augmentation)",
            "total_rows": dataset_metadata.get("total_samples", 0),
            "num_features": len(feature_names),
            "train_samples": dataset_metadata.get("train_samples", 0),
            "test_samples": dataset_metadata.get("test_samples", 0),
            "class_distribution": {
                "legitimate_total": dataset_metadata.get("legitimate_total", 0),
                "phishing_total": dataset_metadata.get("phishing_total", 0),
                "imbalance_ratio": dataset_metadata.get("imbalance_ratio", 1.0),
            },
            "train_test_split": {"test_size": 0.2, "random_state": 42, "stratified": True},
        },
        "hyperparameters": clean_params,
        "test_set_evaluation": {
            "accuracy": test_metrics.get("accuracy"),
            "precision": test_metrics.get("precision"),
            "recall": test_metrics.get("recall"),
            "f1": test_metrics.get("f1"),
            "roc_auc": test_metrics.get("roc_auc"),
            "confusion_matrix": confusion_matrix_breakdown,
        },
        "cross_validation_train": cv_summary,
        "selection_justification": justification,
        "feature_count": len(feature_names),
        "feature_names": feature_names,
    }

    with open(metadata_path, mode="w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Persisted model metadata to %s", metadata_path)

    return model_path, feature_cols_path, metadata_path


# ----------------------------------------------------------------------
# Reproducible Inference Utilities (Consumed by Stage 8)
# ----------------------------------------------------------------------

def load_saved_model_and_columns(
    models_dir: Optional[Path] = None,
) -> Tuple[Any, List[str]]:
    """Load the persisted model artifact and exact expected feature column list.

    Args:
        models_dir: Directory containing phishing_model.joblib and feature_columns.json.

    Returns:
        Tuple of (model_instance, list_of_feature_column_names).
    """
    dir_path = models_dir if models_dir is not None else MODELS_DIR
    model_file = dir_path / "phishing_model.joblib"
    cols_file = dir_path / "feature_columns.json"

    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_file}")
    if not cols_file.exists():
        raise FileNotFoundError(f"Feature columns file not found: {cols_file}")

    model = joblib.load(model_file)
    with open(cols_file, mode="r", encoding="utf-8") as f:
        feature_columns = json.load(f)

    return model, feature_columns


def predict_phishing_sample(
    feature_dict: Dict[str, Any],
    model: Optional[Any] = None,
    feature_columns: Optional[List[str]] = None,
    models_dir: Optional[Path] = None,
) -> Dict[str, Union[bool, float, str]]:
    """Predict phishing probability and classification for a raw combined feature dictionary.

    Aligns the raw dictionary keys into the exact feature order expected by the model,
    filling any missing numeric features with 0/0.0/False.

    Args:
        feature_dict: Dictionary containing extracted URL and HTML features.
        model: Optional pre-loaded model instance.
        feature_columns: Optional pre-loaded list of feature column names.
        models_dir: Directory to load model/columns from if not provided.

    Returns:
        Dictionary with 'is_phishing' (bool), 'phishing_probability' (float), and 'prediction_label' (str).
    """
    if model is None or feature_columns is None:
        model, feature_columns = load_saved_model_and_columns(models_dir=models_dir)

    # Build aligned 1D numeric array in exact column order
    vector = []
    for col in feature_columns:
        val = feature_dict.get(col, 0)
        # Convert boolean or None to numeric
        if isinstance(val, bool):
            numeric_val = 1.0 if val else 0.0
        elif val is None:
            numeric_val = 0.0
        else:
            try:
                numeric_val = float(val)
            except (ValueError, TypeError):
                numeric_val = 0.0
        vector.append(numeric_val)

    # Convert to DataFrame with matching feature column names to avoid feature name mismatch warnings
    X_input = pd.DataFrame([vector], columns=feature_columns)

    pred_binary = int(model.predict(X_input)[0])
    phishing_prob = (
        float(model.predict_proba(X_input)[0][1])
        if hasattr(model, "predict_proba")
        else (1.0 if pred_binary == 1 else 0.0)
    )

    return {
        "is_phishing": bool(pred_binary == 1),
        "phishing_probability": round(phishing_prob, 4),
        "prediction_label": "phishing" if pred_binary == 1 else "legitimate",
    }


def validate_inference_round_trip(
    model: Any,
    feature_columns: List[str],
    sample_df: pd.DataFrame,
    sample_size: int = 10,
) -> bool:
    """Validate that dictionary-based inference matches direct model array prediction.

    Args:
        model: Loaded model instance.
        feature_columns: Expected column names.
        sample_df: Test DataFrame containing feature columns.
        sample_size: Number of samples to test.

    Returns:
        True if all test samples match identically.
    """
    subset = sample_df[feature_columns].head(sample_size)
    direct_preds = model.predict(subset)
    direct_probs = model.predict_proba(subset)[:, 1] if hasattr(model, "predict_proba") else None

    for i, (_, row) in enumerate(subset.iterrows()):
        feat_dict = row.to_dict()
        inf_res = predict_phishing_sample(feat_dict, model=model, feature_columns=feature_columns)

        assert inf_res["is_phishing"] == bool(direct_preds[i] == 1), f"Prediction mismatch at sample {i}"
        if direct_probs is not None:
            assert abs(inf_res["phishing_probability"] - direct_probs[i]) < 1e-3, (
                f"Probability mismatch at sample {i}: {inf_res['phishing_probability']} vs {direct_probs[i]}"
            )

    return True


# ----------------------------------------------------------------------
# Main Execution Pipeline
# ----------------------------------------------------------------------

def tune_and_finalize_pipeline(
    dataset_path: Path = DEFAULT_DATASET_PATH,
    output_dir: Path = MODELS_DIR,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Execute the complete Stage 7 model tuning, selection, and persistence workflow.

    Args:
        dataset_path: Path to processed training dataset CSV.
        output_dir: Directory to save model artifacts.
        random_state: Random seed.

    Returns:
        Summary report dictionary.
    """
    # 1. Load and Split
    X_train, X_test, y_train, y_test, feature_names = load_and_split_dataset(
        dataset_path=dataset_path,
        test_size=0.2,
        random_state=random_state,
    )

    imbalance_ratio = compute_scale_pos_weight(y_train)
    dataset_metadata = {
        "total_samples": len(X_train) + len(X_test),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "legitimate_total": int((y_train == 0).sum() + (y_test == 0).sum()),
        "phishing_total": int((y_train == 1).sum() + (y_test == 1).sum()),
        "imbalance_ratio": imbalance_ratio,
    }

    # 2. Random Forest GridSearchCV
    logger.info("Starting Random Forest tuning...")
    rf_grid = run_random_forest_grid_search(X_train, y_train, random_state=random_state)
    best_rf = rf_grid.best_estimator_
    rf_candidates_summary = extract_grid_search_summary(rf_grid, top_n=5)
    rf_best_params = rf_grid.best_params_

    # Evaluate best RF on held-out test set
    y_pred_rf = best_rf.predict(X_test)
    y_prob_rf = best_rf.predict_proba(X_test)[:, 1]
    rf_eval = evaluate_predictions(y_test, y_pred_rf, y_prob_rf)

    # 3. XGBoost GridSearchCV
    logger.info("Starting XGBoost tuning (scale_pos_weight test value: %.4f)...", imbalance_ratio)
    xgb_grid = run_xgboost_grid_search(X_train, y_train, random_state=random_state)
    best_xgb = xgb_grid.best_estimator_
    xgb_candidates_summary = extract_grid_search_summary(xgb_grid, top_n=5)
    xgb_best_params = xgb_grid.best_params_

    # Evaluate best XGBoost on held-out test set
    y_pred_xgb = best_xgb.predict(X_test)
    y_prob_xgb = best_xgb.predict_proba(X_test)[:, 1]
    xgb_eval = evaluate_predictions(y_test, y_pred_xgb, y_prob_xgb)

    # 4. Model Selection Decision
    rf_top_cv = rf_candidates_summary[0]
    xgb_top_cv = xgb_candidates_summary[0]

    chosen_key, justification = select_best_model(
        rf_eval=rf_eval,
        xgb_eval=xgb_eval,
        rf_cv=rf_top_cv,
        xgb_cv=xgb_top_cv,
        rf_best_params=rf_best_params,
        xgb_best_params=xgb_best_params,
    )

    chosen_model = best_xgb if chosen_key == "xgboost" else best_rf
    chosen_params = xgb_best_params if chosen_key == "xgboost" else rf_best_params
    chosen_eval = xgb_eval if chosen_key == "xgboost" else rf_eval
    chosen_cv = xgb_top_cv if chosen_key == "xgboost" else rf_top_cv

    # 5. Persist Winning Model Artifacts
    model_path, cols_path, meta_path = persist_model_artifacts(
        chosen_model=chosen_model,
        chosen_model_name=chosen_key,
        chosen_params=chosen_params,
        feature_names=feature_names,
        test_metrics=chosen_eval,
        confusion_matrix_breakdown=chosen_eval["confusion_matrix"],
        cv_summary=chosen_cv,
        justification=justification,
        dataset_metadata=dataset_metadata,
        output_dir=output_dir,
    )

    # 6. Verify Inference Round-Trip
    logger.info("Validating inference pipeline round-trip fidelity...")
    loaded_model, loaded_cols = load_saved_model_and_columns(models_dir=output_dir)
    validate_inference_round_trip(loaded_model, loaded_cols, X_test, sample_size=20)
    logger.info("Inference round-trip verification successful across test samples.")

    # ------------------------------------------------------------------
    # Formatted Console Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 85)
    print("        STAGE 7: HYPERPARAMETER TUNING, MODEL SELECTION & PERSISTENCE REPORT")
    print("=" * 85)
    print(f"Dataset: {dataset_metadata['total_samples']} samples | Imbalance: {dataset_metadata['imbalance_ratio']:.2f}:1 (Legit: {dataset_metadata['legitimate_total']}, Phish: {dataset_metadata['phishing_total']})")
    print(f"Train Set: {dataset_metadata['train_samples']} | Held-out Test Set: {dataset_metadata['test_samples']}")
    print("-" * 85)
    print("GRIDSEARCHCV WINNING CONFIGURATIONS (Primary Scoring Metric: Recall):")
    print(f"  - Random Forest Best Params: {rf_best_params}")
    print(f"    * 5-Fold CV: Recall={rf_top_cv['cv_recall_mean']:.4f} (+/- {rf_top_cv['cv_recall_std']:.4f}) | F1={rf_top_cv['cv_f1_mean']:.4f} | Precision={rf_top_cv['cv_precision_mean']:.4f}")
    print(f"  - XGBoost Best Params:       {xgb_best_params}")
    print(f"    * 5-Fold CV: Recall={xgb_top_cv['cv_recall_mean']:.4f} (+/- {xgb_top_cv['cv_recall_std']:.4f}) | F1={xgb_top_cv['cv_f1_mean']:.4f} | Precision={xgb_top_cv['cv_precision_mean']:.4f}")
    print("-" * 85)
    print(f"{'Metric / Evaluation':<32} {'Tuned Random Forest':<26} {'Tuned XGBoost':<26}")
    print("-" * 85)
    print(f"{'Test Accuracy':<32} {rf_eval['accuracy']:<26.4f} {xgb_eval['accuracy']:<26.4f}")
    print(f"{'Test Precision (Phishing)':<32} {rf_eval['precision']:<26.4f} {xgb_eval['precision']:<26.4f}")
    print(f"{'Test Recall (Phishing)':<32} {rf_eval['recall']:<26.4f} {xgb_eval['recall']:<26.4f}")
    print(f"{'Test F1-Score':<32} {rf_eval['f1']:<26.4f} {xgb_eval['f1']:<26.4f}")
    print(f"{'Test ROC-AUC':<32} {rf_eval['roc_auc']:<26.4f} {xgb_eval['roc_auc']:<26.4f}")
    print("-" * 85)
    print(f"HELD-OUT CONFUSION MATRIX (N={len(X_test)}):")
    print(f"  - True Negatives (TN):   RF = {rf_eval['confusion_matrix']['tn']:<5} | XGB = {xgb_eval['confusion_matrix']['tn']:<5}")
    print(f"  - False Positives (FP):  RF = {rf_eval['confusion_matrix']['fp']:<5} | XGB = {xgb_eval['confusion_matrix']['fp']:<5}")
    print(f"  - False Negatives (FN):  RF = {rf_eval['confusion_matrix']['fn']:<5} | XGB = {xgb_eval['confusion_matrix']['fn']:<5}")
    print(f"  - True Positives (TP):   RF = {rf_eval['confusion_matrix']['tp']:<5} | XGB = {xgb_eval['confusion_matrix']['tp']:<5}")
    print("-" * 85)
    print(f"FINAL SELECTED MODEL: {chosen_key.upper()}")
    print(f"Justification: {justification}")
    print("-" * 85)
    print("PERSISTED PRODUCTION ARTIFACTS:")
    print(f"  1. Model File:      {model_path}")
    print(f"  2. Feature Columns: {cols_path}")
    print(f"  3. Metadata File:   {meta_path}")
    print("=" * 85 + "\n")

    return {
        "chosen_model": chosen_key,
        "rf_results": {"best_params": rf_best_params, "eval": rf_eval, "cv": rf_top_cv},
        "xgb_results": {"best_params": xgb_best_params, "eval": xgb_eval, "cv": xgb_top_cv},
        "model_path": str(model_path),
        "feature_columns_path": str(cols_path),
        "metadata_path": str(meta_path),
    }


if __name__ == "__main__":
    tune_and_finalize_pipeline()
