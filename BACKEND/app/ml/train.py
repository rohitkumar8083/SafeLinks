"""ML training pipeline with GroupShuffleSplit by domain and model calibration."""

import argparse
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.features import FEATURE_NAMES, extract_features

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_tld_extractor = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=None, include_psl_private_domains=True)


def _get_registered_domain(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
        ext = _tld_extractor(host)
        reg = getattr(ext, "top_domain_under_public_suffix", None) or host
        return reg or host
    except Exception:
        return "unknown"


def train_pipeline(data_path: Path, out_dir: Path, seed: int = 42) -> None:
    """Trains, compares, calibrates, and persists the phishing classification model."""
    if not data_path.exists():
        raise FileNotFoundError(f"Training dataset not found: {data_path}")

    # Check for synthetic data indicator
    is_synthetic = "SYNTHETIC" in data_path.name.upper()
    if is_synthetic:
        print("\n=======================================================")
        print("SYNTHETIC DATA: metrics are meaningless")
        print("=======================================================\n")

    logger.info("Loading training data from %s", data_path)
    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns")

    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].astype(int)

    # 1. Feature extraction
    logger.info("Extracting %d lexical features across %d URLs...", len(FEATURE_NAMES), len(df))
    feature_rows: list[dict] = []
    groups: list[str] = []

    for raw_url in df["url"]:
        feats = extract_features(raw_url)
        # Convert bools to 0/1 for scikit-learn
        proc_feats = {k: (int(v) if isinstance(v, bool) else v) for k, v in feats.items()}
        feature_rows.append(proc_feats)
        groups.append(_get_registered_domain(raw_url))

    X = pd.DataFrame(feature_rows)[list(FEATURE_NAMES)]
    y = df["label"].to_numpy()
    group_arr = np.array(groups)

    # 2. Group split by registered domain
    unique_domains = len(set(groups))
    logger.info("Total samples: %d across %d registered domains", len(df), unique_domains)

    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
    train_idx, test_idx = next(gss.split(X, y, groups=group_arr))

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    logger.info("Train set: %d samples, Test set: %d samples", len(X_train), len(X_test))

    # Calculate per-feature training medians (used for occlusion attribution at inference)
    per_feature_medians = {col: float(X_train[col].median()) for col in FEATURE_NAMES}

    # 3. Model candidate definition
    candidates = {
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, random_state=seed, class_weight="balanced")),
        ]),
        "RandomForest": RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced_subsample",
            random_state=seed,
            n_jobs=-1,
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(random_state=seed),
    }

    results: dict[str, dict] = {}
    best_name = ""
    best_auc = -1.0
    best_prauc = -1.0
    best_model_obj = None

    print("\n--- Model Evaluation Comparison ---")
    for name, model in candidates.items():
        logger.info("Training candidate %s...", name)
        model.fit(X_train, y_train)

        # Probabilities
        y_proba = model.predict_proba(X_test)[:, 1]
        y_pred = (y_proba >= 0.5).astype(int)

        roc_auc = float(roc_auc_score(y_test, y_proba)) if len(np.unique(y_test)) > 1 else 0.5
        pr_auc = float(average_precision_score(y_test, y_proba)) if len(np.unique(y_test)) > 1 else 0.5
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()

        results[name] = {
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "confusion_matrix": cm,
        }

        print(f"[{name}] ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f} | F1: {f1:.4f} | Acc: {acc:.4f}")

        # Choose best by ROC-AUC, tie-break PR-AUC
        if (roc_auc > best_auc) or (abs(roc_auc - best_auc) < 1e-4 and pr_auc > best_prauc):
            best_auc = roc_auc
            best_prauc = pr_auc
            best_name = name
            best_model_obj = model

    print(f"\nSelected Best Model: {best_name} (ROC-AUC={best_auc:.4f})")

    # High AUC bias warning
    if best_auc > 0.995 and not is_synthetic:
        print("WARNING: ROC-AUC is above 0.995 (suspiciously high: check for dataset bias or leakage)")

    # 4. Probability Calibration
    calib_method = "isotonic" if len(X_train) > 5000 else "sigmoid"
    logger.info("Calibrating %s probabilities using method='%s'...", best_name, calib_method)

    # Use cv=3 if enough samples, otherwise fit on train
    cv_folds = 3 if len(X_train) >= 30 else 2
    calibrated_model = CalibratedClassifierCV(
        estimator=best_model_obj,
        method=calib_method,
        cv=cv_folds,
    )
    calibrated_model.fit(X_train, y_train)

    # 5. Persist model and metadata
    out_dir.mkdir(parents=True, exist_ok=True)
    model_file = out_dir / "phishing_model.joblib"
    meta_file = out_dir / "metadata.json"

    # Save joblib artifact
    joblib.dump(calibrated_model, model_file)
    logger.info("Persisted model artifact to %s", model_file)

    now_utc = datetime.now(UTC)
    version_tag = f"{now_utc.strftime('%Y.%m.%d')}-{best_name}"

    metadata = {
        "version": version_tag,
        "trained_at": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "algorithm": best_name,
        "is_synthetic": is_synthetic,
        "feature_names": list(FEATURE_NAMES),
        "per_feature_training_medians": per_feature_medians,
        "n_samples": len(df),
        "n_domains": unique_domains,
        "class_balance": {
            "phishing": int((y == 1).sum()),
            "benign": int((y == 0).sum()),
        },
        "metrics": results[best_name],
        "model_comparison": results,
    }

    with meta_file.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Saved model metadata to %s", meta_file)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SafeLinks phishing classification model.")
    parser.add_argument("--data", type=str, default="app/ml/data/urls.csv", help="Input training dataset CSV")
    parser.add_argument("--out", type=str, default="app/ml/model", help="Directory to save model artifacts")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    data_p = Path(args.data)
    # Fallback to synthetic dataset if main dataset is absent
    if not data_p.exists() and Path("app/ml/data/urls_SYNTHETIC.csv").exists():
        data_p = Path("app/ml/data/urls_SYNTHETIC.csv")

    train_pipeline(data_path=data_p, out_dir=Path(args.out), seed=args.seed)


if __name__ == "__main__":
    main()
