```markdown
<!-- OpenGraph Meta
og:title: OpenClaw Security Playbook — Multi-Layer Defense for AI Agents
og:description: Production-grade security hardening across 5 architectural layers of the OpenClaw AI agent. Perception → Orchestration → Inference → Execution → Feedback.
og:image: https://raw.githubusercontent.com/openclaw/openclaw-security-playbook/main/assets/og-banner.png
og:url: https://github.com/openclaw/openclaw-security-playbook
og:type: software
twitter:card: summary_large_image
twitter:title: OpenClaw Security Playbook
twitter:description: 5-layer security hardening for autonomous AI agents
-->

<div align="center">

```
   ██████╗ ██████╗ ███████╗███╗   ██╗ ██████╗██╗      █████╗ ██╗    ██╗
  ██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║     ██╔══██╗██║    ██║
  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║██║     ██║     ███████║██║ █╗ ██║
  ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██║     ██║     ██╔══██║██║███╗██║
  ╚██████╔╝██║     ███████╗██║ ╚████║╚██████╗███████╗██║  ██║╚███╔███╔╝
   ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
          ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
          ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
          ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
          ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
          ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
          ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝
                      ┌─────────────────────────┐
                      │   S E C U R I T Y       │
                      │   P L A Y B O O K       │
                      └─────────────────────────┘
```

# OpenClaw Security Playbook

### Production-grade, multi-layer security hardening for the OpenClaw AI agent framework.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Security Policy](https://img.shields.io/badge/Security-Policy%20Enforced-critical?style=for-the-badge&logo=shield)](SECURITY.md)
[![Build Status](https://img.shields.io/github/actions/workflow/status/openclaw/openclaw-security-playbook/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/openclaw/openclaw-security-playbook/actions)
[![Go Report Card](https://img.shields.io/badge/Go%20Report-A+-brightgreen?style=for-the-badge&logo=go)](https://goreportcard.com/report/github.com/openclaw/openclaw-security-playbook)
[![Coverage](https://img.shields.io/badge/Coverage-94%25-brightgreen?style=for-the-badge&logo=codecov)](https://codecov.io/gh/openclaw/openclaw-security-playbook)

[![OWASP Top 10 LLM](https://img.shields.io/badge/OWASP-Top%2010%20LLM%20Compliant-blue?style=flat-square&logo=owasp)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF%20Aligned-informational?style=flat-square)](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework)
[![Releases](https://img.shields.io/github/v/release/openclaw/openclaw-security-playbook?style=flat-square&color=orange)](https://github.com/openclaw/openclaw-security-playbook/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/openclaw/openclaw-security-playbook?style=flat-square&logo=github)](https://github.com/openclaw/openclaw-security-playbook/stargazers)

---

**Defend every layer. Trust no input. Verify every action.**

[Quick Start](#-quick-start) · [Architecture](#-architecture) · [Modules](#-layer-modules) · [Configuration](#%EF%B8%8F-configuration-guide) · [Contributing](#-contributing) · [Security Policy](SECURITY.md)

</div>

---

## 📋 Table of Contents

- [Why This Exists](#-why-this-exists)
- [Threat Model](#-threat-model)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Layer Modules](#-layer-modules)
  - [Layer 1 — Perception](#layer-1--perception)
  - [Layer 2 — Orchestration](#layer-2--orchestration)
  - [Layer 3 — Inference](#layer-3--inference)
  - [Layer 4 — Execution](#layer-4--execution)
  - [Layer 5 — Feedback](#layer-5--feedback)
- [Project Structure](#-project-structure)
- [Configuration Guide](#️-configuration-guide)
- [Benchmarks](#-benchmarks)
- [Compatibility](#-compatibility)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔥 Why This Exists

AI agents are **not just language models** — they are autonomous systems with perception, memory, tool use, and real-world side effects. Traditional application security falls short because:

| Traditional App Security | AI Agent Security (This Playbook) |
|:---|:---|
| Sanitize HTTP inputs | Sanitize **multimodal** inputs (text, image, audio, video, embeddings) |
| Protect databases | Protect **vector stores, episodic memory, shared context windows** |
| Prevent SQL injection | Prevent **prompt injection, jailbreaks, context poisoning** |
| Sandbox code execution | Sandbox **tool calls, skill chains, multi-step plans** |
| Write access logs | Protect **audit logs from AI-driven tampering and hallucination laundering** |

OpenClaw agents operate across **five architectural layers**. An attacker only needs to compromise **one**. This playbook hardens **all five**.

---

## 🎯 Threat Model

This playbook defends against the following adversarial threat categories:

| ID | Threat | Target Layer | Severity |
|:---:|:---|:---:|:---:|
| `T-01` | Multimodal prompt injection (image/audio steganography) | L1 Perception | 🔴 Critical |
| `T-02` | Gateway bypass via malformed routing headers | L2 Orchestration | 🔴 Critical |
| `T-03` | Memory poisoning through adversarial context insertion | L2 Orchestration | 🟠 High |
| `T-04` | Direct / indirect prompt injection | L3 Inference | 🔴 Critical |
| `T-05` | Context window overflow / attention hijacking | L3 Inference | 🟠 High |
| `T-06` | Unauthorized tool invocation / privilege escalation | L4 Execution | 🔴 Critical |
| `T-07` | Container escape via skill chain exploitation | L4 Execution | 🔴 Critical |
| `T-08` | Audit log tampering / evidence destruction | L5 Feedback | 🟠 High |
| `T-09` | Reward hacking / feedback loop manipulation | L5 Feedback | 🟡 Medium |
| `T-10` | Cross-layer exfiltration via chained exploits | L1–L5 | 🔴 Critical |

---

## 🏗 Architecture

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    OPENCLAW SECURITY PLAYBOOK — 5 LAYERS                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   ┌─────────────────────────────────────────────────────────────────────┐    ║
║   │  EXTERNAL INPUTS                                                     │    ║
║   │  [Text] [Image] [Audio] [Video] [API Calls] [Embeddings] [Files]   │    ║
║   └──────────────────────────────┬──────────────────────────────────────┘    ║
║                                  │                                           ║
║                                  ▼                                           ║
║   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓    ║
║   ┃  LAYER 1 ─ PERCEPTION                                             ┃    ║
║   ┃  ┌──────────────┐ ┌──────────────┐ ┌───────────────┐              ┃    ║
║   ┃  │ Input Schema │ │ Multimodal   │ │ Steganography │              ┃    ║
║   ┃  │ Validator    │ │ Sanitizer    │ │ Detector      │              ┃    ║
║   ┃  └──────┬───────┘ └──────┬───────┘ └───────┬───────┘              ┃    ║
║   ┃         └────────────────┼──────────────────┘                      ┃    ║
║   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛    ║
║                               │                                              ║
║                               ▼                                              ║
║   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓    ║
║   ┃  LAYER 2 ─ ORCHESTRATION                                          ┃    ║
║   ┃  ┌──────────────┐ ┌──────────────┐ ┌───────────────┐              ┃    ║
║   ┃  │ Gateway      │ │ Memory       │ │ Rate Limiter  │              ┃    ║
║   ┃  │ Hardener     │ │ Protector    │ │ & Circuit Brk │              ┃    ║
║   ┃  └──────┬───────┘ └──────┬───────┘ └───────┬───────┘              ┃    ║
║   ┃         └────────────────┼──────────────────┘                      ┃    ║
║   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛    ║
║                               │                                              ║
║                               ▼                                              ║
║   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓    ║
║   ┃  LAYER 3 ─ INFERENCE                                              ┃    ║
║   ┃  ┌──────────────┐ ┌──────────────┐ ┌───────────────┐              ┃    ║
║   ┃  │ Prompt       │ │ Context      │ │ Output        │              ┃    ║
║   ┃  │ Firewall     │ │ Scrubber     │ │ Validator     │              ┃    ║
║   ┃  └──────┬───────┘ └──────┬───────┘ └───────┬───────┘              ┃    ║
║   ┃         └────────────────┼──────────────────┘                      ┃    ║
║   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛    ║
║                               │                                              ║
║                               ▼                                              ║
║   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓    ║
║   ┃  LAYER 4 ─ EXECUTION                                              ┃    ║
║   ┃  ┌──────────────┐ ┌──────────────┐ ┌───────────────┐              ┃    ║
║   ┃  │ Container    │ │ Skill        │ │ Syscall       │              ┃    ║
║   ┃  │ Hardener     │ │ Validator    │ │ Filter        │              ┃    ║
║