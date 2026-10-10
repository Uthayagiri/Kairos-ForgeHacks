"""Unit tests for baseline model training, evaluation, and comparison."""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from ml.training.train_baseline_models import (
    evaluate_predictions,
    extract_feature_importances,
    load_and_split_dataset,
    perform_cross_validation,
    train_and_evaluate_baselines,
)


def test_evaluate_predictions_known_values():
    """Verify precision, recall, f1, accuracy, and confusion matrix against manually calculated values."""
    # 4 Negatives (0), 6 Positives (1)
    y_true = [0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
    # Predictions: TN=3, FP=1, FN=1, TP=5
    y_pred = [0, 0, 0, 1, 0, 1, 1, 1, 1, 1]
    y_prob = [0.1, 0.2, 0.3, 0.8, 0.4, 0.9, 0.85, 0.95, 0.7, 0.6]

    metrics = evaluate_predictions(y_true, y_pred, y_prob)

    assert metrics["accuracy"] == 0.8
    assert metrics["precision"] == round(5 / 6, 4)  # 0.8333
    assert metrics["recall"] == round(5 / 6, 4)     # 0.8333
    assert metrics["f1"] == round(5 / 6, 4)         # 0.8333
    assert metrics["confusion_matrix"]["tn"] == 3
    assert metrics["confusion_matrix"]["fp"] == 1
    assert metrics["confusion_matrix"]["fn"] == 1
    assert metrics["confusion_matrix"]["tp"] == 5
    assert metrics["roc_auc"] is not None
    assert 0.0 <= metrics["roc_auc"] <= 1.0


def test_feature_importance_extraction_ordering():
    """Verify feature importances are correctly mapped and strictly descending."""
    class DummyModel:
        feature_importances_ = np.array([0.05, 0.60, 0.15, 0.20])

    feature_names = ["feat_a", "feat_b", "feat_c", "feat_d"]
    model = DummyModel()

    top_3 = extract_feature_importances(model, feature_names, top_n=3)

    assert len(top_3) == 3
    assert top_3[0]["feature"] == "feat_b"
    assert top_3[0]["importance"] == 0.60
    assert top_3[1]["feature"] == "feat_d"
    assert top_3[1]["importance"] == 0.20
    assert top_3[2]["feature"] == "feat_c"
    assert top_3[2]["importance"] == 0.15


def test_synthetic_dataset_training_and_cv(tmp_path):
    """Verify train_test_split, cross validation, and model fitting on a synthetic dataset."""
    np.random.seed(42)
    n_samples = 80
    n_features = 10

    X_data = np.random.randn(n_samples, n_features)
    # Create separable target
    y_data = (X_data[:, 0] + X_data[:, 1] > 0).astype(int)

    feature_names = [f"feat_{i}" for i in range(n_features)]
    df_synthetic = pd.DataFrame(X_data, columns=feature_names)
    df_synthetic["url"] = [f"https://sample-{i}.com" for i in range(n_samples)]
    df_synthetic["label"] = ["phishing" if y == 1 else "legitimate" for y in y_data]
    df_synthetic["label_binary"] = y_data

    dataset_csv = tmp_path / "synthetic_dataset.csv"
    df_synthetic.to_csv(dataset_csv, index=False)

    X_train, X_test, y_train, y_test, feats = load_and_split_dataset(
        dataset_path=dataset_csv,
        test_size=0.25,
        random_state=42,
    )

    assert len(X_train) == 60
    assert len(X_test) == 20
    assert feats == feature_names

    # Test CV for Random Forest
    rf_cv = perform_cross_validation(
        model_factory=lambda: RandomForestClassifier(n_estimators=10, random_state=42),
        X_train=X_train,
        y_train=y_train,
        n_splits=3,
        random_state=42,
    )
    assert rf_cv["folds"] == 3
    assert 0.0 <= rf_cv["cv_accuracy_mean"] <= 1.0
    assert 0.0 <= rf_cv["cv_f1_mean"] <= 1.0

    # Test CV for XGBoost
    xgb_cv = perform_cross_validation(
        model_factory=lambda: XGBClassifier(n_estimators=10, eval_metric="logloss", random_state=42),
        X_train=X_train,
        y_train=y_train,
        n_splits=3,
        random_state=42,
    )
    assert xgb_cv["folds"] == 3
    assert 0.0 <= xgb_cv["cv_accuracy_mean"] <= 1.0
    assert 0.0 <= xgb_cv["cv_f1_mean"] <= 1.0


def test_model_comparison_report_json_schema(tmp_path):
    """Verify train_and_evaluate_baselines generates a valid, schema-compliant JSON report."""
    np.random.seed(42)
    n_samples = 60
    n_features = 8

    X_data = np.random.randn(n_samples, n_features)
    y_data = (X_data[:, 0] > 0).astype(int)

    feature_names = [f"f_{i}" for i in range(n_features)]
    df_syn = pd.DataFrame(X_data, columns=feature_names)
    df_syn["url"] = [f"https://domain-{i}.org" for i in range(n_samples)]
    df_syn["label"] = ["phishing" if y == 1 else "legitimate" for y in y_data]
    df_syn["label_binary"] = y_data

    dataset_csv = tmp_path / "syn_training_data.csv"
    report_json = tmp_path / "model_comparison_report.json"
    df_syn.to_csv(dataset_csv, index=False)

    report = train_and_evaluate_baselines(
        dataset_path=dataset_csv,
        output_report_path=report_json,
        random_state=42,
    )

    assert report_json.exists()

    with open(report_json, mode="r", encoding="utf-8") as f:
        loaded_report = json.load(f)

    # Check top level structure
    assert "dataset_metadata" in loaded_report
    assert "models" in loaded_report
    assert "random_forest" in loaded_report["models"]
    assert "xgboost" in loaded_report["models"]

    # Check model sub-structure
    for model_key in ["random_forest", "xgboost"]:
        model_data = loaded_report["models"][model_key]
        assert "test_metrics" in model_data
        assert "confusion_matrix" in model_data
        assert "cross_validation_train" in model_data
        assert "top_15_features" in model_data

        metrics = model_data["test_metrics"]
        assert all(k in metrics for k in ["accuracy", "precision", "recall", "f1", "roc_auc"])
        assert 0.0 <= metrics["accuracy"] <= 1.0
        assert 0.0 <= metrics["precision"] <= 1.0
        assert 0.0 <= metrics["recall"] <= 1.0
        assert 0.0 <= metrics["f1"] <= 1.0

        cm = model_data["confusion_matrix"]
        assert all(k in cm for k in ["tn", "fp", "fn", "tp"])

        cv = model_data["cross_validation_train"]
        assert "cv_accuracy_mean" in cv
        assert "cv_f1_mean" in cv
        assert cv["folds"] == 5
