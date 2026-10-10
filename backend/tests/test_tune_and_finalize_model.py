"""Unit and integration tests for Stage 7 Model Tuning, Selection, Persistence & Inference."""

import json
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd
import pytest
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from ml.training.tune_and_finalize_model import (
    compute_scale_pos_weight,
    extract_grid_search_summary,
    load_saved_model_and_columns,
    persist_model_artifacts,
    predict_phishing_sample,
    run_random_forest_grid_search,
    run_xgboost_grid_search,
    select_best_model,
    validate_inference_round_trip,
)


@pytest.fixture
def synthetic_data():
    """Generate a reproducible imbalanced synthetic tabular dataset."""
    X_arr, y_arr = make_classification(
        n_samples=120,
        n_features=10,
        n_informative=6,
        n_classes=2,
        weights=[0.75, 0.25],  # 3:1 imbalance
        random_state=42,
    )
    feature_names = [f"feat_{i}" for i in range(10)]
    X = pd.DataFrame(X_arr, columns=feature_names)
    y = pd.Series(y_arr, name="label_binary")
    return X, y, feature_names


def test_compute_scale_pos_weight():
    """Test computing negative-to-positive class weight ratio."""
    # 75 neg, 25 pos -> 3.0
    y1 = [0] * 75 + [1] * 25
    assert compute_scale_pos_weight(y1) == 3.0

    # 100 neg, 50 pos -> 2.0
    y2 = pd.Series([0] * 100 + [1] * 50)
    assert compute_scale_pos_weight(y2) == 2.0

    # Edge case with no positives -> 1.0 fallback
    y3 = [0] * 10
    assert compute_scale_pos_weight(y3) == 1.0


def test_random_forest_grid_search_synthetic(synthetic_data):
    """Test that Random Forest GridSearchCV fits and returns optimal estimator."""
    X, y, _ = synthetic_data
    mini_grid = {
        "n_estimators": [10, 20],
        "max_depth": [5, None],
        "class_weight": [None, "balanced"],
    }
    grid = run_random_forest_grid_search(X, y, param_grid=mini_grid, cv_splits=3, n_jobs=1)

    assert hasattr(grid, "best_estimator_")
    assert isinstance(grid.best_estimator_, RandomForestClassifier)
    assert grid.best_score_ > 0.0

    summary = extract_grid_search_summary(grid, top_n=3)
    assert len(summary) > 0
    assert "params" in summary[0]
    assert "cv_recall_mean" in summary[0]
    assert "cv_f1_mean" in summary[0]


def test_xgboost_grid_search_synthetic(synthetic_data):
    """Test that XGBoost GridSearchCV fits and returns optimal estimator."""
    X, y, _ = synthetic_data
    mini_grid = {
        "n_estimators": [10, 20],
        "max_depth": [3, 5],
        "learning_rate": [0.1],
        "scale_pos_weight": [1.0, 3.0],
    }
    grid = run_xgboost_grid_search(X, y, param_grid=mini_grid, cv_splits=3, n_jobs=1)

    assert hasattr(grid, "best_estimator_")
    assert isinstance(grid.best_estimator_, XGBClassifier)
    assert grid.best_score_ > 0.0

    summary = extract_grid_search_summary(grid, top_n=3)
    assert len(summary) > 0
    assert "params" in summary[0]
    assert "cv_recall_mean" in summary[0]


def test_select_best_model_decision_logic():
    """Test model selection logic under different metric tradeoff conditions."""
    rf_eval = {
        "recall": 0.90,
        "f1": 0.92,
        "precision": 0.94,
        "confusion_matrix": {"tn": 95, "fp": 5, "fn": 10, "tp": 90},
    }
    xgb_eval = {
        "recall": 0.95,
        "f1": 0.94,
        "precision": 0.93,
        "confusion_matrix": {"tn": 93, "fp": 7, "fn": 5, "tp": 95},
    }
    rf_cv = {"cv_recall_mean": 0.89, "cv_recall_std": 0.02}
    xgb_cv = {"cv_recall_mean": 0.94, "cv_recall_std": 0.01}

    # Case 1: XGBoost has higher recall without precision collapse -> XGBoost chosen
    winner, just = select_best_model(rf_eval, xgb_eval, rf_cv, xgb_cv, {}, {})
    assert winner == "xgboost"
    assert "XGBoost" in just

    # Case 2: RF has higher recall -> RF chosen
    rf_eval_higher = dict(rf_eval, recall=0.98, f1=0.96)
    winner2, _ = select_best_model(rf_eval_higher, xgb_eval, rf_cv, xgb_cv, {}, {})
    assert winner2 == "random_forest"


def test_persist_and_load_model_artifacts(tmp_path, synthetic_data):
    """Test saving model, columns, and metadata JSON, then validating loaded artifacts."""
    X, y, feature_names = synthetic_data
    rf = RandomForestClassifier(n_estimators=10, random_state=42)
    rf.fit(X, y)

    test_metrics = {
        "accuracy": 0.95,
        "precision": 0.92,
        "recall": 0.90,
        "f1": 0.91,
        "roc_auc": 0.98,
    }
    cm = {"tn": 80, "fp": 5, "fn": 3, "tp": 32}
    cv_summary = {"cv_recall_mean": 0.89, "cv_recall_std": 0.02}
    dataset_metadata = {
        "total_samples": 120,
        "train_samples": 100,
        "test_samples": 20,
        "legitimate_total": 90,
        "phishing_total": 30,
        "imbalance_ratio": 3.0,
    }

    model_path, cols_path, meta_path = persist_model_artifacts(
        chosen_model=rf,
        chosen_model_name="random_forest",
        chosen_params={"n_estimators": 10},
        feature_names=feature_names,
        test_metrics=test_metrics,
        confusion_matrix_breakdown=cm,
        cv_summary=cv_summary,
        justification="Test selection justification.",
        dataset_metadata=dataset_metadata,
        output_dir=tmp_path,
    )

    assert model_path.exists()
    assert cols_path.exists()
    assert meta_path.exists()

    # Load and check JSON structure
    with open(meta_path, mode="r", encoding="utf-8") as f:
        meta_json = json.load(f)

    assert meta_json["model_type"] == "random_forest"
    assert meta_json["feature_count"] == len(feature_names)
    assert meta_json["feature_names"] == feature_names
    assert meta_json["test_set_evaluation"]["recall"] == 0.90
    assert meta_json["dataset_info"]["class_distribution"]["imbalance_ratio"] == 3.0

    # Load model and columns
    loaded_model, loaded_cols = load_saved_model_and_columns(models_dir=tmp_path)
    assert loaded_cols == feature_names
    assert hasattr(loaded_model, "predict")


def test_predict_phishing_sample_and_round_trip(tmp_path, synthetic_data):
    """Test inference prediction function and round-trip consistency."""
    X, y, feature_names = synthetic_data
    rf = RandomForestClassifier(n_estimators=10, random_state=42)
    rf.fit(X, y)

    persist_model_artifacts(
        chosen_model=rf,
        chosen_model_name="random_forest",
        chosen_params={"n_estimators": 10},
        feature_names=feature_names,
        test_metrics={"accuracy": 0.95},
        confusion_matrix_breakdown={},
        cv_summary={},
        justification="Test",
        dataset_metadata={},
        output_dir=tmp_path,
    )

    loaded_model, loaded_cols = load_saved_model_and_columns(models_dir=tmp_path)

    # 1. Round-trip validation on 10 samples
    assert validate_inference_round_trip(loaded_model, loaded_cols, X, sample_size=10)

    # 2. Test predict_phishing_sample with single dict input
    sample_dict = X.iloc[0].to_dict()
    res = predict_phishing_sample(sample_dict, model=loaded_model, feature_columns=loaded_cols)

    assert "is_phishing" in res
    assert isinstance(res["is_phishing"], bool)
    assert "phishing_probability" in res
    assert 0.0 <= res["phishing_probability"] <= 1.0
    assert res["prediction_label"] in ("phishing", "legitimate")

    # 3. Test handling missing and unknown keys gracefully
    sparse_dict = {"feat_0": 1.5, "unknown_feature": "abc"}
    sparse_res = predict_phishing_sample(sparse_dict, model=loaded_model, feature_columns=loaded_cols)
    assert "is_phishing" in sparse_res
    assert isinstance(sparse_res["phishing_probability"], float)
