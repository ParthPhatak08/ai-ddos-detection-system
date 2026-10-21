"""
Model Training and Comparative Benchmarking Script for AI DDoS Detection
Adheres to strict ML best practices:
1. Featurization ordering: Train/Test split BEFORE scaling to prevent data leakage.
2. Comparative model evaluation (Random Forest, Decision Tree, Logistic Regression).
3. Metric reporting: Accuracy, Precision, Recall, F1-Score, ROC-AUC, FPR.
4. Feature importance extraction and model artifact serialization.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)

FEATURE_COLUMNS = [
    "packets_per_second",
    "bytes_per_second",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "syn_count",
    "average_packet_size",
    "unique_source_ips",
    "unique_destination_ips",
    "connection_count"
]

def train_and_benchmark(
    data_path: str = "data/network_traffic_dataset.csv",
    output_model_path: str = "model/ddos_random_forest.joblib",
    report_path: str = "model/model_report.json"
):
    print(f"[*] Loading dataset from: {data_path}")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Run data/generate_dataset.py first.")
        
    df = pd.read_csv(data_path)
    print(f"[+] Loaded {len(df)} samples. Features: {len(FEATURE_COLUMNS)}")
    
    # Check missing values
    null_counts = df[FEATURE_COLUMNS].isnull().sum().sum()
    if null_counts > 0:
        print(f"[!] Imputing {null_counts} null values with median")
        df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(df[FEATURE_COLUMNS].median())

    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    # Step 1: Strict Train/Test split (80/20) BEFORE fitting scaler
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Split dataset into {len(X_train)} training and {len(X_test)} testing samples.")

    # Step 2: Fit scaler ONLY on training data
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Step 3: Comparative Benchmarking
    candidate_models = {
        "Random Forest (Primary)": RandomForestClassifier(
            n_estimators=100, max_depth=12, random_state=42, n_jobs=-1
        ),
        "Decision Tree (CART)": DecisionTreeClassifier(
            max_depth=10, random_state=42
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=42
        )
    }

    benchmark_results = {}
    best_model_name = "Random Forest (Primary)"

    for name, clf in candidate_models.items():
        print(f"[*] Training {name}...")
        clf.fit(X_train_scaled, y_train)
        y_pred = clf.predict(X_test_scaled)
        y_proba = clf.predict_proba(X_test_scaled)[:, 1] if hasattr(clf, "predict_proba") else y_pred

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc = roc_auc_score(y_test, y_proba)

        benchmark_results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc), 4),
            "false_positive_rate": round(float(fpr), 4),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        }
        print(f"    --> {name}: Accuracy={acc*100:.2f}%, F1={f1*100:.2f}%, FPR={fpr*100:.2f}%")

    # Step 4: Extract Feature Importances from Random Forest
    rf_model = candidate_models[best_model_name]
    importances = rf_model.feature_importances_
    feat_imp = [
        {"feature": feat, "importance": round(float(imp), 4)}
        for feat, imp in sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True)
    ]
    print("\n[+] Top Discriminative Features:")
    for item in feat_imp[:5]:
        print(f"    - {item['feature']}: {item['importance']*100:.1f}%")

    # Step 5: Serialize Artifact
    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    artifact = {
        "model_name": best_model_name,
        "model": rf_model,
        "scaler": scaler,
        "feature_columns": FEATURE_COLUMNS,
        "metrics": benchmark_results[best_model_name],
        "all_benchmarks": benchmark_results,
        "feature_importances": feat_imp
    }
    joblib.dump(artifact, output_model_path)
    print(f"\n[+] Production model artifact serialized to: {output_model_path}")

    # Step 6: Save Model Report
    report = {
        "primary_model": best_model_name,
        "total_training_samples": len(X_train),
        "total_test_samples": len(X_test),
        "feature_count": len(FEATURE_COLUMNS),
        "features": FEATURE_COLUMNS,
        "performance_benchmark": benchmark_results[best_model_name],
        "comparative_benchmarks": benchmark_results,
        "feature_importances": feat_imp
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Detailed evaluation report saved to: {report_path}")
    return artifact

if __name__ == "__main__":
    train_and_benchmark()
