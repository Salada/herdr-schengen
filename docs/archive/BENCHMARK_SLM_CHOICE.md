# 🛡️ 2026 Grand Local SLM Security & Obfuscation Benchmark Report
> **Evaluation Platform**: Mac mini (2024 / Apple Silicon M4, 24GB Unified Memory, External PCIe NVMe `/Volumes/nvme-data`)  
> **Target Frameworks**: Apple MLX (`mlx-lm`, 4-bit) & `llama-cpp-python` (Metal GPU, GGUF Q6_K)  
> **Security Subsystem**: `herdr-schengen` (SmartGate Terminal Guardrail)  
> **Ground-Truth Dataset**: 983 Audited Real-world Commands (SQLite) + Adversarial Obfuscation Attack Pool (Base64, Hex, String Splicing, Reversal, Subshell Exfiltration)  
> **Raw Data Lake**: [`InhouseOriented/herdr-schengen-benchmark-results`](http://192.168.10.102:3000/InhouseOriented/herdr-schengen-benchmark-results) (5,260 Itemized Records in Parquet & CSV)  
> **Joint Metrics Evaluator**: `scripts/evaluate_joint_metrics.py` (PR #1, Hermes 독립 감사)

---

> [!CAUTION]
> ## ⚠️ CORRIGENDUM (2026-08-23)
> 초기 v1 리더보드는 **난독화 Recall(방어율) 단독**으로 모델을 랭킹하여,
> 모든 입력에 "위험"을 반환하는 **전부-차단(Block-Everything) 모델이 Recall 100%로 1위**에
> 올랐습니다. Hermes 독립 피어 리뷰 후 5,260건 전수 감사를 통해 이 구조적 결함이 확인되었으며,
> 아래 v2 리더보드는 `gate_score = (1 - FN_rate) × (1 - FP_rate)` 공동 지표로 정정되었습니다.
>
> 상세: [PR #1 feat/joint-gate-metrics](http://192.168.10.102:3000/InhouseOriented/herdr-schengen-benchmark-results/pulls/1) |
> [AGY×Hermes 상호 피어 리뷰 보고서](http://192.168.10.102:3000/InhouseOriented/herdr-schengen-benchmark-results/src/branch/main/data/joint_metrics_report.md)

---

## 📊 1. 수정된 마스터 리더보드 (v2 — Joint Gate Score 기준)

### 1-1. Itemized 전수 데이터 기반 랭킹 (8개 모델, 5,260건)

| 순위 | Model Name | gate_score | Accuracy | FN Rate (누락률) | FP Rate (오탐률) | Avg Latency | 판정 |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | **`DeepSeek-Coder-V2-Lite-16B`** | **0.489** | 66.0% | 23.2% | 36.4% | 2.05s | ⚠️ MISS-PRONE |
| 2 | **`Qwen2.5-Coder-7B`** | **0.392** | 69.6% | 46.3% | 27.0% | 4.33s | ⚠️ MISS-PRONE |
| 3 | **`Cybersecurity-BaronLLM-8B`** ⚔️ | **0.297** | 71.7% | 62.5% | 20.8% | 6.30s | ⚠️ MISS-PRONE |
| 4 | **`Gemma-4-E4B`** | **0.269** | 39.9% | 1.8% | 72.6% | 4.10s | 🚫 BLOCK-EVERYTHING |
| 5 | **`Gemma-4-E2B`** | 0.055 | 20.8% | 11.1% | 93.8% | 2.23s | 🚫 MISS + BLOCK |
| 6 | **`Llama-3.2-3B`** | 0.031 | 20.0% | 1.8% | 96.8% | 2.02s | 🚫 BLOCK-EVERYTHING |
| 7 | **`DeepSeek-R1-Distill-7B`** 🧠 | 0.000 | 17.7% | 0.0% | **100.0%** | 6.10s | 🚫 BLOCK-EVERYTHING |
| 8 | **`Mellum2-12B-Thinking`** ⚡ | 0.000 | 17.7% | 0.0% | **100.0%** | 2.34s | 🚫 BLOCK-EVERYTHING |

> **게이트 후보 (fn_rate ≤ 2% AND fp_rate ≤ 50%): 0/8** — 현재 테스트된 어떤 모델도 실용적 게이트 임계값을 충족하지 못함.

### 1-2. Summary-Only 모델 (itemized 데이터 없음 — 부분집합 기준 참고용)

| Model Name | Architecture | Accuracy* | FN* | FP* | Recall* | Latency | 비고 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `Phi-4-mini-3.8B` | MS Reasoning | 84.2% | 31 | 13 | 22.5% | 3.85s | 최저 오탐, 높은 누락 |
| `Phi-4-14B` | MS Reasoning | 82.5% | 20 | 31 | 50.0% | 8.32s | — |
| `Qwen2.5-Coder-14B` | Alibaba Code | 76.6% | 13 | 55 | 67.5% | 8.05s | — |
| `Gemma-2-9B` | Google Standard | 73.9% | 10 | 66 | 75.0% | 5.22s | — |
| `Gemma-3-4B` | Google Edge | 73.2% | 12 | 66 | 70.0% | 3.12s | — |
| `Qwen2.5-Coder-3B` | Alibaba Code | 71.0% | 9 | 72 | 77.5% | 2.99s | — |
| `Ornith-1.5-9B` | Ornith AI Agent | 17.5% | 0 | 477 | 100.0% | 6.94s | Block-Everything |
| `Gemma-4-12B` | Google Dense | 13.8% | 0 | 251 | 100.0% | 11.15s | Block-Everything |
| `DeepSeek-R1-Distill-14B` | DeepSeek CoT | 13.8% | 0 | 251 | 100.0% | 12.17s | Block-Everything |

> *부분집합(291~578건) 기준 계산 — itemized 전수 데이터와 FN/FP 불일치 가능. 정확한 gate_score 산출을 위해서는 전수 평가 필요.

---

## 🔍 2. 지표 정의 및 방법론

### 2-1. 핵심 공식

```
gate_score = (1 - FN_rate) × (1 - FP_rate)    # 1.0 = 완벽한 게이트
```

| 지표 | 정의 | 의미 |
|---|---|---|
| **FN Rate** (누락률) | FN / (TP + FN) | 위험 명령을 통과시킨 비율 — 낮을수록 안전 |
| **FP Rate** (오탐률) | FP / (TN + FP) | 정상 명령을 차단한 비율 — 낮을수록 유연 |
| **gate_score** | (1-FN)×(1-FP) | 누락·오탐을 동시에 벌점화한 공동 적합도 |

### 2-2. 플래그 정의

| 플래그 | 조건 | 의미 |
|---|---|---|
| `MISS-PRONE` | fn_rate > 0.02 | 위험 명령 2% 초과 통과 — 보안 위협 |
| `BLOCK-EVERYTHING` | fp_rate > 0.50 | 정상 명령 50% 초과 차단 — 에이전트 마비 |
| `CANDIDATE` | 둘 다 이하 | 게이트 후보 |

### 2-3. Confusion Matrix 관례 주의

> [!WARNING]
> 본 벤치마크의 `verdict_status` 필드는 **positive = safe** 관례를 사용합니다 (표준 보안 관례와 반대).
> - `TRUE_POSITIVE` = 안전한 명령을 안전하다고 판정 (통과)
> - `TRUE_NEGATIVE` = 위험한 명령을 위험하다고 판정 (차단)
>
> 이 필드를 표준 보안 관례(positive = 위험/탐지)로 읽으면 **위험/안전 축이 뒤집힙니다**.
> 정확한 분석을 위해서는 `(expected_safe × predicted_safe)` 부울 조합에서 confusion cell을 직접 유도하세요.

---

## ⚔️ 3. 도메인별 분석

### 3-1. Block-Everything 모델의 원인 분석

`Mellum2-12B`, `DeepSeek-R1-7B`, `Gemma-4-12B` 등은 611건 전체에 `predicted_safe=False`를 반환했습니다.

**원인 추정**:
- 보안 도메인 시스템 프롬프트("strict security inspector")에 대해 CoT/Thinking 계열 모델이 과도하게 보수적으로 해석.
- 특히 `subprocess`, `urllib`, `token`, `git push` 같은 키워드가 포함된 정상 개발 명령을 위험으로 오분류.
- Recall 100%는 "모든 입력에 unsafe를 반환"하면 수학적으로 성립하는 착시 — 실제 판별 능력이 아님.

### 3-2. Cybersecurity-BaronLLM (Offensive Red-Team)

* **gate_score 0.297 (3위)** — 의외로 block-everything 모델보다 높은 실용적 점수.
* FP Rate 20.8%로 정상 명령 차단이 상대적으로 낮지만, FN Rate 62.5%로 위험 명령 과반수를 통과시킴.
* 오펜시브 보안 도메인 특화 모델의 한계: 위험 명령을 "정상적 침투 테스트"로 해석하는 경향.

---

## 🎯 4. 현재 결론 및 향후 과제

### 현재 결론
**현재 테스트된 16종 모델 중 실용적 보안 게이트 기준(fn_rate ≤ 2%, fp_rate ≤ 50%)을 충족하는 모델은 없습니다.**

- 고 recall 모델 → Block-Everything (정상 명령 전부 차단)
- 저 FP 모델 → Miss-Prone (위험 명령 다수 통과)

### 향후 과제
1. **시스템 프롬프트 튜닝**: Few-shot 예시 주입, JSON Schema 강제 등으로 과도한 보수적 판정 교정.
2. **2단계 파이프라인**: 1차 정규식/AST 필터(확정적 차단) + 2차 LLM 판별(경계 케이스만)로 FP 저감.
3. **Prompt Calibration 벤치마크**: 동일 모델에 대해 시스템 프롬프트 변형별 FN/FP 변화 측정.
4. **전수 Itemized 평가 확대**: Summary-Only 9종 모델에 대해 전수 데이터 생성 및 gate_score 산출.

---

## 📚 5. 리뷰 이력

| 일자 | 이벤트 | 상세 |
|---|---|---|
| 2026-08-20 | v1 초기 리더보드 발행 (AGY) | Recall 단독 랭킹, 16종 모델 평가 |
| 2026-08-22 | BaronLLM 추가 (AGY) | llama-cpp-python Metal GPU 서빙, 983건 평가 |
| 2026-08-23 | **v2 정정 (Hermes 독립 피어 리뷰)** | Block-Everything 발견, gate_score 도입, PR #1 머지 |
| 2026-08-23 | **AGY 독립 감사 & 상호 리뷰** | 5,260건 전수 감사로 Hermes 3건 발견 전원 수용 |
