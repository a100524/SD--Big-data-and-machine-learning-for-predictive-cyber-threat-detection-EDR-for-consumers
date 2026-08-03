#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import math
import os
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    make_scorer,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from xgboost import XGBClassifier
RANDOM_SEED = 42
@dataclass
class SplitData:
    """Store the training, validation, and test frames for one evaluation split."""
    name: str
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame
# Apply a signed log transform while preserving the value sign.
def signed_log1p(values: np.ndarray) -> np.ndarray:
    """Apply a signed log transform while preserving the value sign."""
    array = np.asarray(values, dtype=float)
    return np.sign(array) * np.log1p(np.abs(array))
# Calculate confusion-matrix and binary classification metrics.
def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None = None) -> dict[str, float]:
    """Calculate confusion-matrix and binary classification metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    specificity = tn / (tn + fp) if tn + fp else math.nan
    fpr = fp / (tn + fp) if tn + fp else math.nan
    fnr = fn / (fn + tp) if fn + tp else math.nan
    result = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "specificity": float(specificity),
        "false_positive_rate": float(fpr),
        "false_negative_rate": float(fnr),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }
    if scores is not None and len(np.unique(y_true)) == 2:
        result["roc_auc"] = float(roc_auc_score(y_true, scores))
        result["pr_auc"] = float(average_precision_score(y_true, scores))
    else:
        result["roc_auc"] = math.nan
        result["pr_auc"] = math.nan
    return result
# Calculate the reduced metric set used during resampling.
def fast_core_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    """Calculate bootstrap metrics without repeated scikit-learn object creation."""
    y_true = np.asarray(y_true, dtype=np.int8)
    y_pred = np.asarray(y_pred, dtype=np.int8)
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    recall = tp / (tp + fn) if tp + fn else math.nan
    specificity = tn / (tn + fp) if tn + fp else math.nan
    fpr = fp / (tn + fp) if tn + fp else math.nan
    balanced = (recall + specificity) / 2 if math.isfinite(recall) and math.isfinite(specificity) else math.nan
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denominator if denominator else 0.0
    return {
        "mcc": float(mcc),
        "recall": float(recall),
        "false_positive_rate": float(fpr),
        "balanced_accuracy": float(balanced),
    }
# Evaluate candidate decision thresholds on validation predictions.
def threshold_curve(y_true: np.ndarray, scores: np.ndarray) -> pd.DataFrame:
    """Evaluate candidate decision thresholds on validation predictions."""
    candidates = np.unique(np.concatenate([np.linspace(0.01, 0.99, 99), scores]))
    rows = []
    for threshold in candidates:
        pred = (scores >= threshold).astype(int)
        metrics = binary_metrics(y_true, pred, scores)
        rows.append({"threshold": float(threshold), **metrics})
    return pd.DataFrame(rows).sort_values("threshold").reset_index(drop=True)
# Select the frozen threshold using validation MCC and tie rules.
def threshold_from_validation(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, dict[str, float]]:
    """Select the frozen threshold using validation MCC and tie rules."""
    curve = threshold_curve(y_true, scores)
    curve = curve.sort_values(["mcc", "false_positive_rate", "recall", "threshold"], ascending=[False, True, False, True])
    row = curve.iloc[0]
    metrics = {key: float(row[key]) for key in curve.columns if key != "threshold"}
    return float(row["threshold"]), metrics
# Collapse window predictions into one result per run.
def run_level_predictions(frame: pd.DataFrame, scores: np.ndarray, threshold: float, aggregation: str) -> pd.DataFrame:
    """Collapse window predictions into one result per run."""
    temp = frame[["run_id", "label", "family_id", "session_id", "variant_id"]].copy()
    temp["score"] = scores
    if aggregation not in {"max", "mean"}:
        raise ValueError(aggregation)
    aggregated = temp.groupby("run_id", as_index=False).agg(
        label=("label", "first"),
        family_id=("family_id", "first"),
        session_id=("session_id", "first"),
        variant_id=("variant_id", "first"),
        score=("score", aggregation),
    )
    aggregated["prediction"] = (aggregated["score"] >= threshold).astype(int)
    return aggregated
# Estimate run-level metric uncertainty by bootstrap resampling.
def bootstrap_run_metrics(run_frame: pd.DataFrame, repetitions: int, seed: int) -> dict[str, dict[str, float]]:
    """Estimate run-level metric uncertainty by bootstrap resampling."""
    rng = np.random.default_rng(seed)
    values: dict[str, list[float]] = {"mcc": [], "recall": [], "false_positive_rate": [], "balanced_accuracy": []}
    class_frames = {
        int(label): run_frame[run_frame["label"] == label][["label", "prediction"]].to_numpy(dtype=np.int8)
        for label in sorted(run_frame["label"].unique())
    }
    for _ in range(repetitions):
        sampled_parts = []
        for part in class_frames.values():
            if len(part) == 0:
                continue
            indices = rng.integers(0, len(part), len(part))
            sampled_parts.append(part[indices])
        sampled = np.vstack(sampled_parts)
        metrics = fast_core_metrics(sampled[:, 0], sampled[:, 1])
        for key in values:
            values[key].append(metrics[key])
    output: dict[str, dict[str, float]] = {}
    for key, series in values.items():
        arr = np.asarray(series, dtype=float)
        lower = float(np.nanpercentile(arr, 2.5))
        upper = float(np.nanpercentile(arr, 97.5))
        output[key] = {
            "median": float(np.nanmedian(arr)),
            "lower_95": lower,
            "upper_95": upper,
            "interval_width": upper - lower,
        }
    return output
# Calculate one named metric from a prediction frame.
def metric_from_frame(frame: pd.DataFrame, metric: str) -> float:
    """Calculate one named metric from a prediction frame."""
    return fast_core_metrics(frame["label"].to_numpy(), frame["prediction"].to_numpy())[metric]
# Estimate the paired metric difference between two models.
def paired_bootstrap_difference(left: pd.DataFrame, right: pd.DataFrame, repetitions: int, seed: int) -> list[dict[str, Any]]:
    """Estimate the paired metric difference between two models."""
    merged = left[["run_id", "label", "prediction"]].merge(
        right[["run_id", "label", "prediction"]], on=["run_id", "label"], suffixes=("_left", "_right"), validate="one_to_one"
    )
    rng = np.random.default_rng(seed)
    metric_names = ("mcc", "recall", "false_positive_rate", "balanced_accuracy")
    differences = {name: [] for name in metric_names}
    class_arrays = {
        int(label): part[["label", "prediction_left", "prediction_right"]].to_numpy(dtype=np.int8)
        for label, part in merged.groupby("label")
    }
    for _ in range(repetitions):
        sampled_parts = []
        for part in class_arrays.values():
            indices = rng.integers(0, len(part), len(part))
            sampled_parts.append(part[indices])
        sample = np.vstack(sampled_parts)
        left_metrics = fast_core_metrics(sample[:, 0], sample[:, 1])
        right_metrics = fast_core_metrics(sample[:, 0], sample[:, 2])
        for name in metric_names:
            differences[name].append(left_metrics[name] - right_metrics[name])
    outputs = []
    for metric, series in differences.items():
        arr = np.asarray(series, dtype=float)
        lower = float(np.nanpercentile(arr, 2.5))
        upper = float(np.nanpercentile(arr, 97.5))
        outputs.append({
            "metric": metric,
            "median_difference": float(np.nanmedian(arr)),
            "lower_95": lower,
            "upper_95": upper,
            "interval_includes_zero": bool(lower <= 0 <= upper),
        })
    return outputs
# Split training data into stratified training and validation subsets.
def split_train_validation(frame: pd.DataFrame, validation_fraction: float = 0.25) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split training data into stratified training and validation subsets."""
    runs = frame.drop_duplicates("run_id")[["run_id", "label", "family_id"]].copy()
    strata = runs["family_id"].astype(str) + "_" + runs["label"].astype(str)
    try:
        train_ids, val_ids = train_test_split(runs["run_id"], test_size=validation_fraction, random_state=RANDOM_SEED, stratify=strata)
    except ValueError:
        train_ids, val_ids = train_test_split(runs["run_id"], test_size=validation_fraction, random_state=RANDOM_SEED, stratify=runs["label"])
    return frame[frame["run_id"].isin(train_ids)].copy(), frame[frame["run_id"].isin(val_ids)].copy()
# Create the frozen train, validation, and test partitions.
def make_splits(dataset: pd.DataFrame) -> list[SplitData]:
    """Create the frozen train, validation, and test partitions."""
    splits: list[SplitData] = []
    variant_train = dataset[(dataset["variant_id"] == "V1") & (dataset["session_id"].isin(["S01", "S02"]))].copy()
    variant_val = dataset[(dataset["variant_id"] == "V1") & (dataset["session_id"] == "S03")].copy()
    variant_test = dataset[dataset["variant_id"] == "V2"].copy()
    splits.append(SplitData("variant", variant_train, variant_val, variant_test))
    if set(dataset["session_id"].unique()) >= {"S01", "S02", "S03"}:
        splits.append(SplitData("temporal", dataset[dataset["session_id"] == "S01"].copy(), dataset[dataset["session_id"] == "S02"].copy(), dataset[dataset["session_id"] == "S03"].copy()))
    for index, (benign, suspicious) in enumerate((("B1", "S1"), ("B2", "S2"), ("B3", "S3")), start=1):
        test = dataset[dataset["family_id"].isin([benign, suspicious])].copy()
        development = dataset[~dataset["family_id"].isin([benign, suspicious])].copy()
        train = development[development["session_id"].isin(["S01", "S02"])].copy()
        val = development[development["session_id"] == "S03"].copy()
        splits.append(SplitData(f"family_holdout_{index}_{benign}_{suspicious}", train, val, test))
    return splits
# Define the baseline and machine-learning estimators and search grids.
def model_definitions() -> dict[str, tuple[BaseEstimator, dict[str, list[Any]]]]:
    """Define the baseline and machine-learning estimators and search grids."""
    return {
        "logistic_regression": (
            Pipeline([
                ("signed_log1p", FunctionTransformer(signed_log1p, validate=False)),
                ("scale", StandardScaler()),
                ("model", LogisticRegression(max_iter=5000, random_state=RANDOM_SEED, solver="liblinear")),
            ]),
            {"model__C": [0.1, 1.0], "model__class_weight": ["balanced"]},
        ),
        "random_forest": (
            RandomForestClassifier(random_state=RANDOM_SEED, n_jobs=-1),
            {"n_estimators": [200], "max_depth": [None, 5], "min_samples_leaf": [1], "class_weight": ["balanced"]},
        ),
        "xgboost": (
            XGBClassifier(random_state=RANDOM_SEED, n_jobs=-1, eval_metric="logloss", tree_method="hist"),
            {"n_estimators": [100], "max_depth": [2, 4], "learning_rate": [0.10], "subsample": [0.8], "colsample_bytree": [0.8]},
        ),
    }
# Choose a valid cross-validation split count for the available groups.
def safe_cv_splits(train: pd.DataFrame) -> int:
    """Choose a valid cross-validation split count for the available groups."""
    run_counts = train.drop_duplicates("run_id").groupby("label")["run_id"].count()
    minimum = int(run_counts.min()) if not run_counts.empty else 2
    return max(2, min(3, minimum))
# Calculate detection delay from the active-window start.
def alert_delay(frame: pd.DataFrame, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    """Calculate detection delay from the active-window start."""
    temp = frame[["run_id", "label", "window_index", "window_duration_s"]].copy()
    temp["score"] = scores
    suspicious = temp[temp["label"] == 1]
    delays = []
    undetected = 0
    for _, run in suspicious.groupby("run_id"):
        detected = run[run["score"] >= threshold].sort_values("window_index")
        if detected.empty:
            undetected += 1
        else:
            row = detected.iloc[0]
            delays.append(float(row["window_index"] * row["window_duration_s"]))
    return {
        "detected_runs": len(delays),
        "undetected_runs": undetected,
        "median_seconds": float(np.median(delays)) if delays else math.nan,
        "iqr_seconds": float(np.percentile(delays, 75) - np.percentile(delays, 25)) if delays else math.nan,
        "minimum_seconds": float(np.min(delays)) if delays else math.nan,
        "maximum_seconds": float(np.max(delays)) if delays else math.nan,
    }
# Calculate false alerts per benign observation hour.
def false_alerts_per_benign_hour(frame: pd.DataFrame, predictions: np.ndarray) -> float:
    """Calculate false alerts per benign observation hour."""
    benign = frame["label"].to_numpy() == 0
    false_alerts = int(np.sum(predictions[benign] == 1))
    benign_seconds = float(frame.loc[benign, "window_duration_s"].sum())
    return false_alerts / (benign_seconds / 3600.0) if benign_seconds else math.nan
# Calculate evaluation metrics for each family or subgroup.
def per_group_metrics(run_frame: pd.DataFrame, group_column: str) -> list[dict[str, Any]]:
    """Calculate evaluation metrics for each family or subgroup."""
    rows = []
    for group, part in run_frame.groupby(group_column):
        metrics = binary_metrics(part["label"].to_numpy(), part["prediction"].to_numpy(), part["score"].to_numpy())
        rows.append({group_column: group, "runs": int(len(part)), **metrics})
    return rows
# Extract and normalise feature-importance values from the fitted model.
def feature_importance(model: BaseEstimator, features: list[str]) -> pd.DataFrame:
    """Extract and normalise feature-importance values from the fitted model."""
    estimator: Any = model
    if isinstance(model, Pipeline):
        estimator = model.named_steps.get("model", model)
    if hasattr(estimator, "feature_importances_"):
        values = np.asarray(estimator.feature_importances_, dtype=float)
    elif hasattr(estimator, "coef_"):
        values = np.abs(np.asarray(estimator.coef_, dtype=float).reshape(-1))
    else:
        values = np.zeros(len(features), dtype=float)
    return pd.DataFrame({"feature": features, "importance": values}).sort_values("importance", ascending=False)
# Create the benign reference distribution used by live inference.
def benign_reference(frame: pd.DataFrame, features: list[str]) -> dict[str, Any]:
    """Create the benign reference distribution used by live inference."""
    benign = frame[frame["label"] == 0]
    output: dict[str, Any] = {"source": "training benign windows only", "features": {}}
    for feature in features:
        series = benign[feature].astype(float)
        std = float(series.std(ddof=0))
        output["features"][feature] = {
            "mean": float(series.mean()),
            "standard_deviation": std,
            "median": float(series.median()),
            "q1": float(series.quantile(0.25)),
            "q3": float(series.quantile(0.75)),
        }
    return output
# Create the saved model card text from the frozen evaluation results.
def model_card_text(metadata: dict[str, Any], selected_result: dict[str, Any]) -> str:
    """Create the saved model card text from the frozen evaluation results."""
    return f"""# Model card
## Model identity
- Protocol: EDR-MSC-FINAL
- Model: {metadata['model']}
- Feature set: {metadata['feature_set']}
- Selection design: temporal validation
- Probability threshold: {metadata['threshold']}
## Intended use
The model is intended for the controlled comparison of aggregated endpoint telemetry with exact-indicator and rule baselines in the frozen four-VM MSc laboratory.
## Out-of-scope use
The model must not be deployed as a production security product, used against third-party systems, or presented as proof of unrestricted unknown-malware detection or human consumer usability.
## Training and evaluation
Session S01 supplied temporal training data, S02 supplied temporal validation and threshold selection data, and S03 supplied the sealed temporal test. Variant and entire-family-holdout designs were evaluated separately. All windows from one run remained in one group.
## Preprocessing
The selected pipeline and its fitted transformations were trained only on the training partition. Logistic regression used a signed log transformation and standardisation inside the pipeline. Tree models used raw numerical counts.
## Selected temporal-test results
```json
{json.dumps(selected_result, indent=2)}
```
## Explanation method
Live explanations compare the observed feature vector with means and standard deviations calculated from benign training windows only. The explanation reports deviations, not causation.
## Known limitations
- Synthetic, non-destructive behavioural families.
- One Windows endpoint and one frozen laboratory environment.
- Multiple correlated windows per run.
- No participant-based usability evaluation.
- Hybrid features include prior Wazuh and Suricata rule decisions.
- Performance may change after software, configuration, telemetry, or behaviour changes.
## Maintenance conditions
Retraining and revalidation are required after a feature-schema change, material telemetry change, operating-system upgrade, sensor reconfiguration, or sustained distribution shift. The dataset, schema, source code, and selected model must remain linked to every reported result by file name and experiment record.
"""
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Execute all frozen splits, model searches, threshold selection, evaluation, tracking, and artefact output."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--bootstrap-repetitions", type=int, default=200)
    parser.add_argument("--mlflow-uri", default=os.getenv("MLFLOW_TRACKING_URI", ""))
    parser.add_argument("--experiment-name", default="EDR-LAB")
    parser.add_argument("--quick", action="store_true", help="Reduced validation run only. Do not use for formal results.")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    dataset = pd.read_csv(args.dataset)
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    if schema.get("protocol_id") != "EDR-MSC-FINAL":
        raise SystemExit("Feature schema protocol_id is not EDR-MSC-FINAL")
    feature_sets = {"telemetry_only": schema["telemetry_only_features"], "hybrid": schema["hybrid_features"]}
    if args.quick:
        args.bootstrap_repetitions = min(args.bootstrap_repetitions, 200)
    required_metadata = {"run_id", "label", "family_id", "variant_id", "session_id", "window_index", "window_duration_s"}
    missing_metadata = required_metadata - set(dataset.columns)
    if missing_metadata:
        raise SystemExit(f"Missing metadata columns: {sorted(missing_metadata)}")
    if dataset.groupby("run_id")["label"].nunique().max() != 1:
        raise SystemExit("A run appeared with more than one label.")
    all_results: list[dict[str, Any]] = []
    run_predictions: dict[tuple[str, str], pd.DataFrame] = {}
    selected_candidates: list[dict[str, Any]] = []
    mlflow = None
    try:
        import mlflow as mlflow_module
        mlflow = mlflow_module
        tracking_uri = args.mlflow_uri or (args.output_dir / "mlruns").resolve().as_uri()
        mlflow.set_tracking_uri(tracking_uri)
        mlflow.set_experiment(args.experiment_name)
    except Exception as exc:
        (args.output_dir / "mlflow-warning.txt").write_text(str(exc), encoding="utf-8")
    for split in make_splits(dataset):
        if split.train.empty or split.validation.empty or split.test.empty:
            raise SystemExit(f"Split {split.name} contains an empty partition")
        for baseline_column, baseline_name in (("exact_indicator_prediction", "exact_indicator_baseline"), ("rule_baseline_prediction", "rule_baseline")):
            if baseline_column not in dataset.columns:
                continue
            test_scores = split.test[baseline_column].astype(float).to_numpy()
            test_pred = (test_scores >= 0.5).astype(int)
            run_max = run_level_predictions(split.test, test_scores, 0.5, "max")
            result = {
                "design": split.name,
                "feature_set": "baseline",
                "model": baseline_name,
                "best_parameters": {},
                "threshold": 0.5,
                "validation_metrics": None,
                "window_metrics": {**binary_metrics(split.test["label"].to_numpy(), test_pred, test_scores), "false_alerts_per_benign_hour": false_alerts_per_benign_hour(split.test, test_pred)},
                "run_metrics_max": binary_metrics(run_max["label"].to_numpy(), run_max["prediction"].to_numpy(), run_max["score"].to_numpy()),
                "run_metrics_mean": None,
                "bootstrap_run_max": bootstrap_run_metrics(run_max, args.bootstrap_repetitions, RANDOM_SEED + len(all_results)),
                "alert_delay": alert_delay(split.test, test_scores, 0.5),
                "per_family_run_metrics": per_group_metrics(run_max, "family_id"),
                "per_session_run_metrics": per_group_metrics(run_max, "session_id"),
                "train_runs": int(split.train["run_id"].nunique()),
                "validation_runs": int(split.validation["run_id"].nunique()),
                "test_runs": int(split.test["run_id"].nunique()),
            }
            all_results.append(result)
            run_predictions[(split.name, baseline_name)] = run_max
            run_max.to_csv(args.output_dir / f"predictions-{split.name}-{baseline_name}-run-max.csv", index=False)
        for feature_set_name, features in feature_sets.items():
            missing_features = [feature for feature in features if feature not in dataset.columns]
            if missing_features:
                raise SystemExit(f"Missing features: {missing_features}")
            X_train = split.train[features]
            y_train = split.train["label"].astype(int)
            groups = split.train["run_id"]
            X_val = split.validation[features]
            y_val = split.validation["label"].astype(int).to_numpy()
            X_test = split.test[features]
            y_test = split.test["label"].astype(int).to_numpy()
            definitions = model_definitions()
            if args.quick:
                definitions = {"logistic_regression": definitions["logistic_regression"]}
            for model_name, (estimator, param_grid) in definitions.items():
                if args.quick:
                    param_grid = {key: values[:1] for key, values in param_grid.items()}
                cv = StratifiedGroupKFold(n_splits=safe_cv_splits(split.train), shuffle=True, random_state=RANDOM_SEED)
                search = GridSearchCV(estimator, param_grid=param_grid, scoring=make_scorer(matthews_corrcoef), cv=cv, n_jobs=1, refit=True, error_score="raise", return_train_score=True)
                run_context = mlflow.start_run(run_name=f"{split.name}-{feature_set_name}-{model_name}") if mlflow else None
                try:
                    search.fit(X_train, y_train, groups=groups)
                    model = search.best_estimator_
                    validation_scores = model.predict_proba(X_val)[:, 1]
                    curve = threshold_curve(y_val, validation_scores)
                    curve_path = args.output_dir / f"threshold-curve-{split.name}-{feature_set_name}-{model_name}.csv"
                    curve.to_csv(curve_path, index=False)
                    threshold, validation_metrics = threshold_from_validation(y_val, validation_scores)
                    test_scores = model.predict_proba(X_test)[:, 1]
                    test_pred = (test_scores >= threshold).astype(int)
                    window_metrics = binary_metrics(y_test, test_pred, test_scores)
                    window_metrics["false_alerts_per_benign_hour"] = false_alerts_per_benign_hour(split.test, test_pred)
                    run_max = run_level_predictions(split.test, test_scores, threshold, "max")
                    run_mean = run_level_predictions(split.test, test_scores, threshold, "mean")
                    run_max_metrics = binary_metrics(run_max["label"].to_numpy(), run_max["prediction"].to_numpy(), run_max["score"].to_numpy())
                    run_mean_metrics = binary_metrics(run_mean["label"].to_numpy(), run_mean["prediction"].to_numpy(), run_mean["score"].to_numpy())
                    bootstrap = bootstrap_run_metrics(run_max, args.bootstrap_repetitions, RANDOM_SEED + len(all_results))
                    delay = alert_delay(split.test, test_scores, threshold)
                    identifier = f"{feature_set_name}-{model_name}"
                    prediction_frame = split.test[["run_id", "session_id", "family_id", "variant_id", "label", "window_index", "window_duration_s"]].copy()
                    prediction_frame["score"] = test_scores
                    prediction_frame["prediction"] = test_pred
                    prediction_frame.to_csv(args.output_dir / f"predictions-{split.name}-{identifier}-window.csv", index=False)
                    run_max.to_csv(args.output_dir / f"predictions-{split.name}-{identifier}-run-max.csv", index=False)
                    run_mean.to_csv(args.output_dir / f"predictions-{split.name}-{identifier}-run-mean.csv", index=False)
                    run_predictions[(split.name, identifier)] = run_max
                    errors = prediction_frame[prediction_frame["label"] != prediction_frame["prediction"]].copy()
                    errors["error_type"] = np.where(errors["label"] == 1, "false_negative", "false_positive")
                    errors.to_csv(args.output_dir / f"errors-{split.name}-{identifier}.csv", index=False)
                    importance_path = args.output_dir / f"feature-importance-{split.name}-{identifier}.csv"
                    feature_importance(model, features).to_csv(importance_path, index=False)
                    result = {
                        "design": split.name,
                        "feature_set": feature_set_name,
                        "model": model_name,
                        "best_parameters": search.best_params_,
                        "best_cross_validation_mcc": float(search.best_score_),
                        "threshold": threshold,
                        "validation_metrics": validation_metrics,
                        "window_metrics": window_metrics,
                        "run_metrics_max": run_max_metrics,
                        "run_metrics_mean": run_mean_metrics,
                        "bootstrap_run_max": bootstrap,
                        "alert_delay": delay,
                        "per_family_run_metrics": per_group_metrics(run_max, "family_id"),
                        "per_session_run_metrics": per_group_metrics(run_max, "session_id"),
                        "train_runs": int(split.train["run_id"].nunique()),
                        "validation_runs": int(split.validation["run_id"].nunique()),
                        "test_runs": int(split.test["run_id"].nunique()),
                    }
                    all_results.append(result)
                    if mlflow:
                        mlflow.log_params({"design": split.name, "feature_set": feature_set_name, "model": model_name, "threshold": threshold, **{str(k): str(v) for k, v in search.best_params_.items()}})
                        mlflow.log_metrics({f"validation_{k}": float(v) for k, v in validation_metrics.items() if isinstance(v, (int, float)) and math.isfinite(float(v))})
                        mlflow.log_metrics({f"test_run_{k}": float(v) for k, v in run_max_metrics.items() if isinstance(v, (int, float)) and math.isfinite(float(v))})
                        mlflow.set_tags({"protocol_id": "EDR-MSC-FINAL"})
                        mlflow.log_artifact(str(curve_path))
                        mlflow.log_artifact(str(importance_path))
                    if split.name == "temporal" and feature_set_name == "telemetry_only":
                        selected_candidates.append({
                            "validation_mcc": float(validation_metrics["mcc"]),
                            "validation_fpr": float(validation_metrics["false_positive_rate"]),
                            "validation_recall": float(validation_metrics["recall"]),
                            "model_name": model_name,
                            "feature_set": feature_set_name,
                            "model": model,
                            "threshold": threshold,
                            "features": features,
                            "training_frame": split.train.copy(),
                            "result": result,
                        })
                finally:
                    if mlflow and run_context:
                        mlflow.end_run()
    comparison_rows: list[dict[str, Any]] = []
    for design in sorted({key[0] for key in run_predictions}):
        candidates = {name: frame for (d, name), frame in run_predictions.items() if d == design}
        names = sorted(candidates)
        for left_index, left_name in enumerate(names):
            for right_name in names[left_index + 1 :]:
                try:
                    differences = paired_bootstrap_difference(candidates[left_name], candidates[right_name], args.bootstrap_repetitions, RANDOM_SEED + len(comparison_rows))
                except ValueError:
                    continue
                for difference in differences:
                    comparison_rows.append({"design": design, "left": left_name, "right": right_name, **difference})
    pd.DataFrame(comparison_rows).to_csv(args.output_dir / "paired-bootstrap-model-differences.csv", index=False)
    results_path = args.output_dir / "evaluation-results.json"
    results_path.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    pd.json_normalize(all_results).to_csv(args.output_dir / "evaluation-results-flat.csv", index=False)
    if not selected_candidates:
        raise SystemExit("No temporal telemetry-only model candidate was produced. Confirm that sessions S01, S02, and S03 exist.")
    selected_candidates.sort(key=lambda item: (item["validation_mcc"], -item["validation_fpr"], item["validation_recall"]), reverse=True)
    selected = selected_candidates[0]
    model_path = args.output_dir / "selected-telemetry-model.joblib"
    joblib.dump(selected["model"], model_path)
    reference = benign_reference(selected["training_frame"], selected["features"])
    reference_path = args.output_dir / "selected-benign-reference.json"
    reference_path.write_text(json.dumps(reference, indent=2), encoding="utf-8")
    metadata = {
        "protocol_id": "EDR-MSC-FINAL",
        "selection_design": "temporal",
        "model": selected["model_name"],
        "feature_set": selected["feature_set"],
        "features": selected["features"],
        "threshold": selected["threshold"],
        "validation_mcc": selected["validation_mcc"],
        "validation_false_positive_rate": selected["validation_fpr"],
        "validation_recall": selected["validation_recall"],
        "run_score_primary": "maximum window probability",
        "limitations": [
            "Synthetic non-destructive behaviours",
            "One Windows endpoint",
            "No human usability study",
            "Not evidence of unrestricted malware detection",
        ],
    }
    metadata_path = args.output_dir / "selected-telemetry-model.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (args.output_dir / "model-card.md").write_text(model_card_text(metadata, selected["result"]), encoding="utf-8")
    if mlflow:
        with mlflow.start_run(run_name="selected-temporal-telemetry-model"):
            mlflow.log_params({"model": selected["model_name"], "feature_set": selected["feature_set"], "threshold": selected["threshold"]})
            mlflow.log_metrics({"validation_mcc": selected["validation_mcc"], "validation_false_positive_rate": selected["validation_fpr"], "validation_recall": selected["validation_recall"]})
            mlflow.set_tags({"protocol_id": "EDR-MSC-FINAL", "selected_model": "true"})
            mlflow.log_artifact(str(model_path))
            mlflow.log_artifact(str(metadata_path))
            mlflow.log_artifact(str(reference_path))
            mlflow.log_artifact(str(args.output_dir / "model-card.md"))
    print(f"Wrote {results_path} with {len(all_results)} result records")
    print(f"Selected model: {selected['model_name']} threshold={selected['threshold']:.6f}")
    return 0
# Run the command-line entry point only when this file is executed directly.
if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=UserWarning)
    raise SystemExit(main())
