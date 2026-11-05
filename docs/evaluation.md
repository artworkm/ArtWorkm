# SentinelAI — Model Evaluation Report

## 1. Overview

This document summarizes the evaluation of SentinelAI's intrusion detection Random Forest model using CICIDS2017 and UNSW-NB15 datasets.

Four experiments were conducted to examine model performance under different evaluation conditions:

1. CICIDS2017 random train/test split using all 69 features.
2. CICIDS2017 per-file row-order split using all 69 features.
3. CICIDS2017 training and testing using 8 shared features.
4. Cross-dataset evaluation: train on CICIDS2017 and test on UNSW-NB15 using 8 shared features.

The purpose is to evaluate not only accuracy but also generalization, false-positive rates, and the effects of dataset distribution differences.

## 2. Evaluation Results

| Experiment | Features | Accuracy | Macro Precision | Macro Recall | Macro F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|
| CICIDS2017 Random Split | 69 | 0.9949 | 0.8466 | 0.9896 | 0.8730 | 0.5815% |
| CICIDS2017 Ordered Split | 69 | 0.9823 | 0.6886 | 0.7031 | 0.6632 | 1.3264% |
| CICIDS2017 → CICIDS2017 | 8 | 0.9956 | 0.9909 | 0.9921 | 0.9915 | 0.2863% |
| CICIDS2017 → UNSW-NB15 | 8 | 0.4494 | 0.2247 | 0.5000 | 0.3101 | 0.0000% |

**Metric definitions:**

- Accuracy: Proportion of correctly classified records.
- Macro Precision: Average precision across classes, giving each class equal weight.
- Macro Recall: Average recall across classes, giving each class equal weight.
- Macro F1: Average F1-score across classes.
- False Positive Rate (FPR): Proportion of benign records incorrectly classified as attacks.

For multiclass experiments, FPR treats BENIGN as the negative class and all other classes as attacks. The cross-dataset experiment uses binary BENIGN-versus-ATTACK classification.

## 3. Random Split Evaluation

The Random Forest model was evaluated using a stratified 80/20 random train/test split on CICIDS2017 with all 69 features.

Results:

- Accuracy: 99.49%
- Macro Precision: 84.66%
- Macro Recall: 98.96%
- Macro F1: 87.30%
- FPR: 0.5815%

The model achieved high accuracy and recall. However, the relatively lower macro precision and macro F1 indicate that performance was not equally strong across all attack categories. In particular, Bot detection had poor precision despite high recall.

## 4. Ordered Split Evaluation

A per-file row-order split was performed, using the first 70% of each source dataset file for training and the remaining 30% for testing.

Results:

- Accuracy: 98.23%
- Macro Precision: 68.86%
- Macro Recall: 70.31%
- Macro F1: 66.32%
- FPR: 1.3264%

Performance declined compared with the random split. Bot detection remained particularly weak, while DoS detection also experienced a noticeable reduction in recall.

The test partition contained zero WebAttack records, so WebAttack performance could not be evaluated. Its zero-support class is included in the reported macro averages and affects their interpretation.

**Important limitation:** The source files were divided by row order, but chronological ordering was not independently verified using timestamps. Therefore, this experiment is a per-file ordered holdout rather than a confirmed chronological evaluation.

## 5. Eight-Feature CICIDS2017 Evaluation

To support cross-dataset evaluation, the CICIDS2017 model was trained and tested using eight shared features:

1. Flow Duration
2. Total Fwd Packets
3. Total Backward Packets
4. Fwd Packets Length Total
5. Bwd Packets Length Total
6. Flow Bytes/s
7. Flow Packets/s
8. Avg Packet Size

The problem was converted into binary classification:

- 0 = BENIGN
- 1 = ATTACK

Results:

- Accuracy: 99.56%
- Macro Precision: 99.09%
- Macro Recall: 99.21%
- Macro F1: 99.15%
- FPR: 0.2863%

The model performed strongly when evaluated on the same dataset using the reduced feature set. However, this result does not establish that the model will generalize to other network environments.

## 6. Cross-Dataset Evaluation: CICIDS2017 → UNSW-NB15

The Random Forest model trained on CICIDS2017 using the eight shared features was evaluated on the UNSW-NB15 testing dataset.

The UNSW-NB15 dataset contained 82,332 records:

- 37,000 benign records.
- 45,332 attack records.

Results at the default classification threshold of 0.5:

- Accuracy: 44.94%
- Macro Precision: 22.47%
- Macro Recall: 50.00%
- Macro F1: 31.01%
- FPR: 0.00%
- ROC-AUC: 0.4007
- Average Precision: 0.5148

The confusion matrix was:

| Actual / Predicted | BENIGN | ATTACK |
|---|---:|---:|
| BENIGN | 37,000 | 0 |
| ATTACK | 45,332 | 0 |

The model classified every UNSW-NB15 record as benign and failed to detect any attacks.

Although the false-positive rate was zero, this was not evidence of a successful intrusion detection system. The model achieved this result by failing to identify attacks altogether.

### 6.1 Threshold Analysis

Several classification thresholds were examined to determine whether lowering the default threshold could improve detection.

| Threshold | Predicted Attacks | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|---:|
| 0.50 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| 0.40 | 2 | 0.5000 | 0.0000 | 0.0000 | 0.0000 |
| 0.30 | 25 | 0.9600 | 0.0005 | 0.0011 | 0.0000 |
| 0.20 | 990 | 0.0929 | 0.0020 | 0.0040 | 0.0243 |
| 0.10 | 1,729 | 0.2389 | 0.0091 | 0.0176 | 0.0356 |
| 0.05 | 3,032 | 0.3420 | 0.0229 | 0.0429 | 0.0539 |
| 0.01 | 9,540 | 0.3398 | 0.0715 | 0.1182 | 0.1702 |

Lowering the threshold increased the number of detected attacks but also increased false positives. Even at a threshold of 0.01, attack recall reached only 7.15%, with a false-positive rate of 17.02%.

Therefore, threshold adjustment alone does not solve the cross-dataset generalization problem.

## 7. Distribution Shift and Deployment Implications

The cross-dataset experiment demonstrates substantial distribution shift between CICIDS2017 and UNSW-NB15. Although both datasets were transformed into the same eight feature names, their statistical distributions differed significantly. For example, the median Flow Bytes/s was approximately 2,738.9 in CICIDS2017 training data and 305,372.3 in UNSW-NB15. The model's ROC-AUC of 0.4007 indicates that its attack probability ranking did not transfer reliably to the external dataset. The results show that high accuracy on one dataset does not guarantee reliable detection in a different network environment. Consequently, SentinelAI should not rely on a model trained on one dataset without additional cross-environment validation and suitable training data.

## 8. Conclusion

The experiments show that evaluation methodology and dataset selection significantly affect intrusion detection performance.

The random-split and same-dataset reduced-feature experiments produced strong results, while the per-file ordered holdout showed weaker performance. Most importantly, cross-dataset testing revealed that the CICIDS2017-trained model failed to generalize to UNSW-NB15.

These findings establish the importance of realistic evaluation, distribution-shift analysis, and external dataset validation when developing a dependable intrusion detection system.

**Evaluation status:** Phase 1C model evaluation experiments documented.