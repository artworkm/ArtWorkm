# SentinelAI — Model Evaluation Report

## 1\. Overview

This document summarizes the evaluation of SentinelAI's intrusion detection Random Forest model using CICIDS2017 and UNSW-NB15 datasets.

Four experiments were conducted to examine model performance under different evaluation conditions:

1. CICIDS2017 random train/test split using all 69 features.
2. CICIDS2017 per-file row-order split using all 69 features.
3. CICIDS2017 training and testing using 8 shared features.
4. Cross-dataset evaluation: train on CICIDS2017 and test on UNSW-NB15 using 8 shared features.

The purpose is to evaluate not only accuracy but also generalization, false-positive rates, and the effects of dataset distribution differences.

## 2\. Evaluation Results

|Experiment|Features|Accuracy|Macro Precision|Macro Recall|Macro F1|FPR|
|-|-:|-:|-:|-:|-:|-:|
|CICIDS2017 Random Split|69|0.9949|0.8466|0.9896|0.8730|0.5815%|
|CICIDS2017 Ordered Split|69|0.9823|0.6886|0.7031|0.6632|1.3264%|
|CICIDS2017 → CICIDS2017|8|0.9956|0.9909|0.9921|0.9915|0.2863%|
|CICIDS2017 → UNSW-NB15|8|0.4494|0.2247|0.5000|0.3101|0.0000%|

**Metric definitions:**

* Accuracy: Proportion of correctly classified records.
* Macro Precision: Average precision across classes, giving each class equal weight.
* Macro Recall: Average recall across classes, giving each class equal weight.
* Macro F1: Average F1-score across classes.
* False Positive Rate (FPR): Proportion of benign records incorrectly classified as attacks.

For multiclass experiments, FPR treats BENIGN as the negative class and all other classes as attacks. The cross-dataset experiment uses binary BENIGN-versus-ATTACK classification.

## 3\. Random Split Evaluation

The Random Forest model was evaluated using a stratified 80/20 random train/test split on CICIDS2017 with all 69 features.

Results:

* Accuracy: 99.49%
* Macro Precision: 84.66%
* Macro Recall: 98.96%
* Macro F1: 87.30%
* FPR: 0.5815%

The model achieved high accuracy and recall. However, the relatively lower macro precision and macro F1 indicate that performance was not equally strong across all attack categories. In particular, Bot detection had poor precision despite high recall.

## 4\. Ordered Split Evaluation

A per-file row-order split was performed, using the first 70% of each source dataset file for training and the remaining 30% for testing.

Results:

* Accuracy: 98.23%
* Macro Precision: 68.86%
* Macro Recall: 70.31%
* Macro F1: 66.32%
* FPR: 1.3264%

Performance declined compared with the random split. Bot detection remained particularly weak, while DoS detection also experienced a noticeable reduction in recall.

The test partition contained zero WebAttack records, so WebAttack performance could not be evaluated. Its zero-support class is included in the reported macro averages and affects their interpretation.

**Important limitation:** The source files were divided by row order, but chronological ordering was not independently verified using timestamps. Therefore, this experiment is a per-file ordered holdout rather than a confirmed chronological evaluation.

## 5\. Eight-Feature CICIDS2017 Evaluation

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

* 0 = BENIGN
* 1 = ATTACK

Results:

* Accuracy: 99.56%
* Macro Precision: 99.09%
* Macro Recall: 99.21%
* Macro F1: 99.15%
* FPR: 0.2863%

The model performed strongly when evaluated on the same dataset using the reduced feature set. However, this result does not establish that the model will generalize to other network environments.

## 6\. Cross-Dataset Evaluation: CICIDS2017 → UNSW-NB15

The Random Forest model trained on CICIDS2017 using the eight shared features was evaluated on the UNSW-NB15 testing dataset.

The UNSW-NB15 dataset contained 82,332 records:

* 37,000 benign records.
* 45,332 attack records.

Results at the default classification threshold of 0.5:

* Accuracy: 44.94%
* Macro Precision: 22.47%
* Macro Recall: 50.00%
* Macro F1: 31.01%
* FPR: 0.00%
* ROC-AUC: 0.4007
* Average Precision: 0.5148

The confusion matrix was:

|Actual / Predicted|BENIGN|ATTACK|
|-|-:|-:|
|BENIGN|37,000|0|
|ATTACK|45,332|0|

The model classified every UNSW-NB15 record as benign and failed to detect any attacks.

Although the false-positive rate was zero, this was not evidence of a successful intrusion detection system. The model achieved this result by failing to identify attacks altogether.

### 6.1 Threshold Analysis

Several classification thresholds were examined to determine whether lowering the default threshold could improve detection.

|Threshold|Predicted Attacks|Precision|Recall|F1|FPR|
|-:|-:|-:|-:|-:|-:|
|0.50|0|0.0000|0.0000|0.0000|0.0000|
|0.40|2|0.5000|0.0000|0.0000|0.0000|
|0.30|25|0.9600|0.0005|0.0011|0.0000|
|0.20|990|0.0929|0.0020|0.0040|0.0243|
|0.10|1,729|0.2389|0.0091|0.0176|0.0356|
|0.05|3,032|0.3420|0.0229|0.0429|0.0539|
|0.01|9,540|0.3398|0.0715|0.1182|0.1702|

Lowering the threshold increased the number of detected attacks but also increased false positives. Even at a threshold of 0.01, attack recall reached only 7.15%, with a false-positive rate of 17.02%.

Therefore, threshold adjustment alone does not solve the cross-dataset generalization problem.

## 7\. Distribution Shift and Deployment Implications

The cross-dataset experiment demonstrates substantial distribution shift between CICIDS2017 and UNSW-NB15. Although both datasets were transformed into the same eight feature names, their statistical distributions differed significantly. For example, the median Flow Bytes/s was approximately 2,738.9 in CICIDS2017 training data and 305,372.3 in UNSW-NB15. The model's ROC-AUC of 0.4007 indicates that its attack probability ranking did not transfer reliably to the external dataset. The results show that high accuracy on one dataset does not guarantee reliable detection in a different network environment. Consequently, SentinelAI should not rely on a model trained on one dataset without additional cross-environment validation and suitable training data.

## 8\. Conclusion

The experiments show that evaluation methodology and dataset selection significantly affect intrusion detection performance.

The random-split and same-dataset reduced-feature experiments produced strong results, while the per-file ordered holdout showed weaker performance. Most importantly, cross-dataset testing revealed that the CICIDS2017-trained model failed to generalize to UNSW-NB15.

These findings establish the importance of realistic evaluation, distribution-shift analysis, and external dataset validation when developing a dependable intrusion detection system.

**Evaluation status:** Phase 1C model evaluation experiments documented.

## Phase 2 — RAG Retrieval and AI Threat Analysis Evaluation

### 9. RAG Retrieval Evaluation

**Evaluation setup**

- Knowledge collection: `security_knowledge`
- Embedding model: `nomic-embed-text`
- Vector database: Qdrant
- Number of evaluation questions: 30
- Retrieval depth: Top 5 results
- Evaluation method: Expected MITRE technique IDs or document/playbook titles checked against retrieved metadata.

**Results**

| Metric | Correct retrievals | Score |
|---|---:|---:|
| hit@1 | 20/30 | 66.7% |
| hit@3 | 26/30 | 86.7% |
| hit@5 | 26/30 | 86.7% |

**Result: Passed.** The hit@5 score of 86.7% exceeds the project target of 80%.

**Missed questions**

1. Network port scanning and open services — expected T1046; related Active Scanning techniques were retrieved instead.
2. Failed logins followed by a successful login — relevant authentication material was retrieved, but the expected brute-force playbook was not in the top five.
3. Network controls for DDoS mitigation — relevant MITRE techniques were retrieved, but the expected OWASP document was not in the top five.
4. Reducing exposed network services — related techniques were retrieved, but T1046 was not in the top five.

**Limitations**

This evaluation checks predefined expected identifiers and titles in the retrieved metadata. It measures retrieval coverage rather than the factual correctness of generated answers. The four missed questions provide opportunities for future retrieval improvements.

### 10. Manual AI Threat Analysis Evaluation

Twenty detections were manually reviewed to assess the quality of the generated AI threat analyses.

Each analysis was assessed using four criteria:

- Summary accuracy: 0–5 points.
- Attack technique accuracy: 0–5 points.
- Evidence relevance: 0–5 points.
- Recommended action quality: 0–5 points.

The maximum score per detection was 20 points.

| ID | Detection | Summary | Technique | Evidence | Actions | Total |
|---:|---|---:|---:|---:|---:|---:|
| 1 | WebAttack | 4 | 4 | 4 | 4 | 16 |
| 2 | BruteForce | 4 | 5 | 5 | 4 | 18 |
| 3 | BruteForce | 4 | 5 | 5 | 5 | 19 |
| 4 | Bot | 4 | 4 | 4 | 5 | 17 |
| 5 | BruteForce | 4 | 5 | 5 | 5 | 19 |
| 6 | DDoS | 5 | 5 | 5 | 4 | 19 |
| 7 | DoS | 4 | 4 | 3 | 4 | 15 |
| 8 | PortScan | 5 | 5 | 5 | 5 | 20 |
| 9 | WebAttack | 4 | 4 | 4 | 4 | 16 |
| 10 | BruteForce | 4 | 5 | 5 | 4 | 18 |
| 11 | BruteForce | 4 | 5 | 5 | 4 | 18 |
| 12 | WebAttack | 4 | 4 | 4 | 4 | 16 |
| 13 | WebAttack | 4 | 4 | 4 | 4 | 16 |
| 14 | DoS | 4 | 4 | 3 | 4 | 15 |
| 15 | DoS | 4 | 4 | 3 | 4 | 15 |
| 16 | DDoS | 4 | 5 | 4 | 4 | 17 |
| 17 | DDoS | 5 | 5 | 4 | 4 | 18 |
| 18 | PortScan | 5 | 5 | 5 | 4 | 19 |
| 19 | PortScan | 4 | 5 | 4 | 4 | 17 |
| 20 | Bot | 4 | 3 | 4 | 5 | 16 |
| **Total** | **20 detections** | **84** | **89** | **85** | **84** | **344/400** |

**Overall manual score: 86%.**

#### 10.1 Key observations

- BruteForce analyses generally retrieved relevant authentication and password-guessing knowledge, including MITRE T1110 and its sub-techniques.
- DDoS analyses generally identified T1498 and provided relevant network traffic filtering and mitigation recommendations.
- PortScan analyses successfully retrieved the port-scan playbook and relevant MITRE techniques T1046 and T1595.
- WebAttack analyses commonly identified T1190, although the available event information did not independently prove successful exploitation or SQL injection.
- Some DoS analyses included T1046, which is related to network service discovery rather than denial of service.
- Bot analysis retrieved the botnet command-and-control playbook. However, the relationship between T1071 and the retrieved MITRE evidence should be improved.
- Similar detections sometimes produced repetitive recommendations.

#### 10.2 Confidence interpretation

The Random Forest confidence value represents the model's prediction probability for the selected class. The LLM confidence represents its assessment of the available supporting evidence.

These values measure different things and should not be interpreted interchangeably. A high Random Forest probability does not independently confirm an attack.

The backend's `grounded` flag indicates that at least one cited source ID matches a retrieved source. It does not independently establish that every generated claim is fully supported.

#### 10.3 Evaluation limitations

- The manual assessment is subjective and should not be treated as a formal independent security analyst benchmark.
- Retrieved knowledge provides context but does not independently prove that an attack occurred.
- Synthetic or dataset-replayed detections are not equivalent to live production network telemetry.
- Threat intelligence providers were not configured with API keys during this evaluation, so external IP reputation enrichment was limited.
- Human verification remains necessary before containment or other consequential security actions.

### 11. Phase 2 Conclusion

The Phase 2 implementation demonstrates a functioning retrieval-augmented threat analysis workflow using Qdrant, Ollama embeddings, MITRE ATT&CK, CISA KEV, OWASP documentation, and security playbooks.

The retrieval evaluation achieved 86.7% hit@5, exceeding the 80% target. The twenty manually reviewed AI analyses received an aggregate score of 344/400 (86%).

The evaluation also identified areas for improvement, including more precise technique mapping, better event-specific evidence, reduced repetition in recommendations, and stronger validation of generated claims.

The results demonstrate a working knowledge-grounded analysis capability, but do not establish that the system is ready for autonomous incident response or production deployment.