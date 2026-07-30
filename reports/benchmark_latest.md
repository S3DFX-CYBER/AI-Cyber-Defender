# 📏 TENET AI Detection Engine Benchmark Report
**Generated At:** `2026-07-30T18:51:14.567323+00:00`  
**Dataset:** `data/benchmark_dataset.json`  
**Total Samples:** 30

## 📊 Summary Performance Metrics
| Metric | Value |
| --- | --- |
| **Precision** | `1.0000` |
| **Recall** | `1.0000` |
| **F1 Score** | `1.0000` |
| **Accuracy** | `1.0000` |
| **AUC-ROC** | `1.0000` |
| **Avg Latency** | `0.39 ms` |
| **P95 Latency** | `0.4 ms` |

## 🧩 Confusion Matrix
| | Predicted Benign | Predicted Malicious |
| --- | --- | --- |
| **Actual Benign** | True Negative (TN): **15** | False Positive (FP): **0** |
| **Actual Malicious** | False Negative (FN): **0** | True Positive (TP): **15** |

## 📂 Per-Category Metrics
| Category | Samples | Precision | Recall | F1 Score | Accuracy |
| --- | --- | --- | --- | --- | --- |
| `prompt_injection` | 3 | `1.0000` | `1.0000` | `1.0000` | `1.0000` |
| `jailbreak` | 7 | `1.0000` | `1.0000` | `1.0000` | `1.0000` |
| `data_extraction` | 5 | `1.0000` | `1.0000` | `1.0000` | `1.0000` |
| `benign` | 15 | `0.0000` | `0.0000` | `0.0000` | `1.0000` |
