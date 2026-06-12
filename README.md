# LexEvidence Disclosure Agent

**Audit AI agent transparency, responsibility and evidence trails before deployment.**

LexEvidence Disclosure Agent is a local-first audit tool for AI agent transparency and responsibility. It analyzes synthetic logs of AI-agent activity and checks whether an agent disclosed its AI status, identified its operator, stayed within its scope of authority, required human approval where needed, preserved an audit trail, and produced enough information to reconstruct a basic chain of custody.

## Why this matters

Organizations increasingly deploy chatbots, email assistants and workflow agents before they have practical controls for transparency, accountability and auditability. This creates legal, compliance and trust risks. Non-compliance with AI Act transparency duties may lead to significant administrative fines under Article 99.

## What the MVP does

- Upload or select a synthetic JSON log of AI-agent activity.
- Validate the log structure safely.
- Audit the log against 10 Lex Turbo Agent Disclosure Standard principles.
- Score each principle from 0 to 2.
- Classify message-level and overall risk as low, medium, high or critical.
- Generate a Markdown audit report.
- Generate a disclosure note and internal policy snippet.
- Run locally with no Azure runtime dependency.

## Tech stack

- Python
- Streamlit
- pandas
- GitHub and VS Code
- Developed with GitHub Copilot assistance where available

This Creative Apps version is designed to work locally. Microsoft Foundry / Foundry IQ is not used as a runtime in this version and is listed only as a future roadmap option.

## Install and run

```bash
pip install -r requirements.txt
streamlit run app.py
```

You can also run a console audit:

```bash
python -m agent.analyzer data/synthetic_logs/example_critical_risk.json
```

## Synthetic data only

The demo data is fictional. Do not upload real client files, legal case materials, real emails, medical data, private conversations or confidential information.

## Responsible AI

This tool is an auditor, not an autonomous decision-maker. It does not provide legal advice. It uses deterministic scoring rules so every finding includes evidence and justification.

## Repository structure

```text
agent/                  core parser, analyzer, classifier and generators
data/synthetic_logs/    four fictional logs: low, medium, high, critical
data/knowledge/         lightweight standard and AI Act context
app.py                  Streamlit interface
```

## Future roadmap

A future version may add Microsoft Foundry / Foundry IQ as an optional reasoning layer for second-opinion analysis and better grounding. That integration is planned, not used in this local MVP.
