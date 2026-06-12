# Architecture

LexEvidence Disclosure Agent is a local-first audit pipeline.

```text
User
  |
  v
Streamlit UI (app.py)
  |
  v
Parser and validator (agent/parser.py)
  |
  v
Rule engine: 10 Lex Turbo disclosure principles (agent/analyzer.py)
  |
  v
Risk classifier (agent/risk_classifier.py)
  |
  v
Report and policy generators (agent/report_generator.py, agent/policy_generator.py)
  |
  v
Markdown audit report download
```

Side inputs:

- `data/knowledge/lex_turbo_standard.md`
- `data/knowledge/ai_act_art50.md`
- synthetic logs in `data/synthetic_logs/`

Development layer:

- GitHub
- VS Code
- GitHub Copilot assistance where available

Future layer, not used in this version:

- Microsoft Foundry / Foundry IQ as an optional reasoning layer.
