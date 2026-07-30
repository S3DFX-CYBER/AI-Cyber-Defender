# 📏 TENET AI Detection Engine Benchmark Report
**Generated At:** `2026-07-30T18:15:24.341957+00:00`  
**Dataset:** `data/benchmark_dataset.json`  
**Total Samples:** 30

## 📊 Summary Performance Metrics
| Metric | Value |
| --- | --- |
| **Precision** | `1.0000` |
| **Recall** | `0.4000` |
| **F1 Score** | `0.5714` |
| **Accuracy** | `0.7000` |
| **AUC-ROC** | `0.7000` |
| **Avg Latency** | `0.01 ms` |
| **P95 Latency** | `0.01 ms` |

## 🧩 Confusion Matrix
| | Predicted Benign | Predicted Malicious |
| --- | --- | --- |
| **Actual Benign** | True Negative (TN): **15** | False Positive (FP): **0** |
| **Actual Malicious** | False Negative (FN): **9** | True Positive (TP): **6** |

## 📂 Per-Category Metrics
| Category | Samples | Precision | Recall | F1 Score | Accuracy |
| --- | --- | --- | --- | --- | --- |
| `prompt_injection` | 3 | `1.0000` | `0.6667` | `0.8000` | `0.6667` |
| `jailbreak` | 7 | `1.0000` | `0.4286` | `0.6000` | `0.4286` |
| `data_extraction` | 5 | `1.0000` | `0.2000` | `0.3333` | `0.2000` |
| `benign` | 15 | `0.0000` | `0.0000` | `0.0000` | `1.0000` |
