# 🛡️ 2026 Grand Local SLM Security & Obfuscation Benchmark Report
> **Evaluation Platform**: Mac mini (2024 / Apple Silicon M4, 24GB Unified Memory, External PCIe NVMe `/Volumes/nvme-data`)  
> **Target Frameworks**: Apple MLX (`mlx-lm`, 4-bit) & `llama-cpp-python` (Metal GPU, GGUF Q6_K)  
> **Security Subsystem**: `herdr-schengen` (SmartGate Terminal Guardrail)  
> **Ground-Truth Dataset**: 983 Audited Real-world Commands (SQLite) + Adversarial Obfuscation Attack Pool (Base64, Hex, String Splicing, Reversal, Subshell Exfiltration)  
> **Raw Data Lake**: Hosted in [`InhouseOriented/herdr-schengen-benchmark-results`](http://192.168.10.102:3000/InhouseOriented/herdr-schengen-benchmark-results) (5,260 Itemized Records in Parquet & CSV)

---

## 📊 1. Executive Summary & Master Leaderboard

| Model Name | Architecture / Vendor | Active / Total Params | Obfuscation Recall (방어율) | False Negatives (치명적 누락) | False Positives (과도한 차단) | Decision Latency (평균 지연) | Overall Security Tier |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`DeepSeek-R1-Distill-7B`** 🧠 | CoT Reasoning / DeepSeek | 7B | **100.0%** | **0 건 (완벽)** | 251 | **6.23s** | 🏆 **Tier 1 (최우수 CoT 가드)** |
| **`JetBrains Mellum2-12B-Thinking`** ⚡ | MoE Thinking / JetBrains | 2.5B / 12B | **100.0%** | **0 건 (완벽)** | 251 | **2.43s (초고속)** | 🏆 **Tier 1 (최고 속도 MoE 가드)** |
| **`Gemma-4-E2B`** ⚡ | Edge Distilled / Google | 2B | **100.0%** | **0 건 (완벽)** | 251 | **2.14s (초고속)** | 🥈 **Tier 2 (초경량 에지 가드)** |
| **`Gemma-4-E4B`** | Edge Distilled / Google | 4B | **100.0%** | **0 건 (완벽)** | 251 | **4.12s** | 🥈 **Tier 2 (에지 밸런서)** |
| **`DeepSeek-R1-Distill-14B`** 🧠 | CoT Reasoning / DeepSeek | 14B | **100.0%** | **0 건 (완벽)** | 251 | **12.17s** | 🥈 **Tier 2 (심층 정밀 감사관)** |
| **`Ornith-1.5-9B`** | Agentic Coder / Ornith AI | 9B | **100.0%** | **0 건 (완벽)** | 477 | **6.94s** | 🥈 **Tier 2 (에이전트 특화 가드)** |
| **`Gemma-4-12B`** | Dense Standard / Google | 12B | **100.0%** | **0 건 (완벽)** | 251 | **11.15s** | 🥉 **Tier 3 (헤비 덴스 가드)** |
| **`DeepSeek-Coder-V2-Lite`** | MoE Coder / DeepSeek | 2.4B / 16B | **76.8%** | **23 건** | 174 | **2.05s** | 🥉 **Tier 3 (고속 코딩 분석기)** |
| **`Llama-3.2-3B`** | General Agent / Meta | 3B | **82.5%** | **7 건** | 118 | **1.98s (전체 1위)** ⚡ | 🥉 **Tier 3 (초고속 범용 SLM)** |
| **`Qwen2.5-Coder-3B`** | Code Specialist / Alibaba | 3B | **77.5%** | **9 건** | 72 | **2.98s** | ⚠️ **Tier 4 (경량 코더)** |
| **`Gemma-2-9B`** | General Standard / Google | 9B | **75.0%** | **10 건** | 66 | **5.21s** | ⚠️ **Tier 4 (표준 모델)** |
| **`Gemma-3-4B`** | Edge Standard / Google | 4B | **70.0%** | **12 건** | 66 | **3.12s** | ⚠️ **Tier 4 (Gemma 3 표준)** |
| **`Qwen2.5-Coder-14B`** | Code Specialist / Alibaba | 14B | **67.5%** | **13 건** | 55 | **8.05s** | ⚠️ **Tier 4 (대형 코더)** |
| **`Microsoft Phi-4`** | Reasoning / Microsoft | 14B | **50.0%** | **20 건** | 31 | **8.32s** | ⚠️ **Tier 4 (MS 14B 풀 모델)** |
| **`Qwen2.5-Coder-7B`** | Code Specialist / Alibaba | 7B | **45.0%** | **22 건** | **22 (최저 오탐)** | **4.48s** | ⚠️ **Tier 4 (개발 유연성 특화)** |
| **`Cybersecurity-BaronLLM`** ⚔️ | Offensive Red-Team / GGUF | 8B | **37.5%** | **110 건 (공격 관대)** | 168 | **6.30s** | ⚔️ **Offensive Specialist (방어용 부적합)** |
| **`Phi-4-mini`** | Reasoning / Microsoft | 3.8B | **22.5%** | **31 건 (최다 누락)** | **13** | **3.85s** | ❌ **Tier 5 (난독화 극도 취약)** |

---

## 🔍 2. 핵심 분석: `Cybersecurity-BaronLLM` 실측 결과와 시사점

### ⚔️ 오펜시브 특화 모델(Red-Team)의 딜레마
* **방어율 37.5% / 치명적 누락 110건 발생**:
  * `BaronLLM`은 취약점 분석 및 침투 테스트 도구로서, **위험한 명령어(Base64 eval, 토큰 유출 셸 등)를 '차단해야 할 대상'이 아니라 '정상적인 익스플로잇/보안 테스트 시나리오'로 인식**하는 경향이 뚜렷했습니다.
  * 따라서 방어용 스마트게이트(Guardrail) 목적으로는 부적합하지만, **"공격 페이로드 심층 역공학 분석기"**로서의 도메인 특성을 입증했습니다.

---

## 🎯 3. Mac mini M4 (24GB) 최종 권장 모델 매트릭스

1. 🥇 **실시간 터미널 스마트게이트 1위**: **`JetBrains Mellum2-12B-Thinking`** (2.4초 지연, 100% 방어)
2. 🥈 **초저지연 에지 가드 1위**: **`Gemma-4-E2B`** (2.1초 지연, 1.4GB RAM 점유, 100% 방어)
3. 🥉 **심층 CoT 정밀 감사관 1위**: **`DeepSeek-R1-Distill-7B`** (6.2초 지연, 완벽한 난독화 역공학)
