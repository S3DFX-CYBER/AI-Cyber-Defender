"""
Evaluation metrics calculation module for detection benchmarking.
"""
from typing import Dict, List, Any


def calculate_metrics(y_true: List[int], y_scores: List[float], threshold: float = 0.5) -> Dict[str, Any]:
    """
    Calculate classification metrics: Precision, Recall, F1, Accuracy, AUC-ROC, and Confusion Matrix.

    Args:
        y_true: List of ground truth binary labels (1 for malicious, 0 for benign).
        y_scores: List of continuous risk scores (0.0 to 1.0).
        threshold: Decision threshold to convert risk score to binary prediction.

    Returns:
        Dict containing precision, recall, f1_score, accuracy, auc_roc, confusion_matrix, total_samples.
    """
    if not y_true or len(y_true) != len(y_scores):
        return {
            "total_samples": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "accuracy": 0.0,
            "auc_roc": 0.0,
            "confusion_matrix": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
            "threshold": threshold,
        }

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for true_label, score in zip(y_true, y_scores):
        pred_label = 1 if score >= threshold else 0
        if true_label == 1 and pred_label == 1:
            tp += 1
        elif true_label == 0 and pred_label == 1:
            fp += 1
        elif true_label == 0 and pred_label == 0:
            tn += 1
        elif true_label == 1 and pred_label == 0:
            fn += 1

    total = len(y_true)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    auc_roc = _compute_auc_roc(y_true, y_scores)

    return {
        "total_samples": total,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "accuracy": round(accuracy, 4),
        "auc_roc": round(auc_roc, 4),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "threshold": threshold,
    }


def _compute_auc_roc(y_true: List[int], y_scores: List[float]) -> float:
    """
    Compute Area Under Receiver Operating Characteristic Curve (AUC-ROC)
    using rank-sum statistic (Mann-Whitney U test statistic formulation).
    """
    positives = [score for label, score in zip(y_true, y_scores) if label == 1]
    negatives = [score for label, score in zip(y_true, y_scores) if label == 0]

    n_pos = len(positives)
    n_neg = len(negatives)

    if n_pos == 0 or n_neg == 0:
        return 0.5  # Undefined/Neutral baseline AUC when single class present

    # Combine and sort scores while tracking ranks
    combined = sorted([(score, label) for label, score in zip(y_true, y_scores)], key=lambda x: x[0])
    
    # Handle rank sum with tie handling
    rank_sum_pos = 0.0
    i = 0
    n = len(combined)
    
    while i < n:
        j = i
        while j < n and combined[j][0] == combined[i][0]:
            j += 1
        # Average rank for tied group (1-indexed ranks)
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            if combined[k][1] == 1:
                rank_sum_pos += avg_rank
        i = j

    # AUC = (U_stat) / (n_pos * n_neg)
    u_stat = rank_sum_pos - (n_pos * (n_pos + 1)) / 2.0
    auc = u_stat / (n_pos * n_neg)
    return max(0.0, min(1.0, auc))
