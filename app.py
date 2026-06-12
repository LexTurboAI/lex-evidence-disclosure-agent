"""LexEvidence Disclosure Agent — local Streamlit UI."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from agent.analyzer import analyze
from agent.parser import LogValidationError, parse_log
from agent.policy_generator import generate_disclosure_note, generate_policy_snippet
from agent.report_generator import GAP_RECOMMENDATIONS, build_report
from agent.risk_classifier import CLASS_LABELS, LEVEL_DOTS, LEVEL_LABELS

EXAMPLES_DIR = Path(__file__).parent / "data" / "synthetic_logs"
POINT_DOTS = {2: "🟢", 1: "🟡", 0: "🔴"}


def load_input() -> tuple[bytes, str] | None:
    st.sidebar.header("Input data")
    st.sidebar.caption("Use synthetic logs only. Do not upload real client or confidential data.")
    examples = sorted(EXAMPLES_DIR.glob("*.json")) if EXAMPLES_DIR.exists() else []
    source = st.sidebar.radio("Source", ["Example synthetic log", "Upload JSON file"] if examples else ["Upload JSON file"])
    if source == "Example synthetic log" and examples:
        chosen = st.sidebar.selectbox("Example", examples, format_func=lambda p: p.name)
        return chosen.read_bytes(), chosen.name
    uploaded = st.sidebar.file_uploader("AI agent log JSON", type=["json", "txt"])
    if uploaded:
        return uploaded.getvalue(), uploaded.name
    return None


def main() -> None:
    st.set_page_config(page_title="LexEvidence Disclosure Agent", page_icon="⚖️", layout="wide")
    st.title("⚖️ LexEvidence Disclosure Agent")
    st.markdown("Local-first audit tool for AI agent transparency, responsibility and evidence trails.")
    st.info("Demo tool. Synthetic data only. Auditor, not legal advice and not an autonomous decision-maker.")

    payload = load_input()
    if payload is None:
        st.warning("Choose an example log or upload a synthetic JSON log from the sidebar.")
        st.stop()

    raw, filename = payload
    try:
        log = parse_log(raw, filename)
        result = analyze(log)
    except LogValidationError as exc:
        st.error(str(exc))
        st.stop()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Compliance", f"{result.total}/{result.max_total}")
    c2.metric("Overall risk", f"{LEVEL_DOTS[result.overall]} {LEVEL_LABELS[result.overall]}")
    c3.metric("Messages", len(result.log.messages))
    c4.metric("Gaps", len(result.gaps))
    st.caption(f"File: `{result.log.source_filename}` · SHA-256: `{result.log.sha256[:24]}…` · analyzed: {result.analyzed_at}")

    tabs = st.tabs(["10 principles", "Risk matrix", "Gaps", "Policy output", "Report"])

    with tabs[0]:
        rules_df = pd.DataFrame({
            "#": [r.number for r in result.rules],
            "Principle": [r.name for r in result.rules],
            "Score": [f"{POINT_DOTS[r.points]} {r.points}/2" for r in result.rules],
            "Evidence": [r.evidence for r in result.rules],
            "Justification": [r.justification for r in result.rules],
        })
        st.dataframe(rules_df, hide_index=True, use_container_width=True)

    with tabs[1]:
        risk_df = pd.DataFrame({
            "Message": [m.index for m in result.message_risks],
            "Action class": [CLASS_LABELS[m.action_cls] for m in result.message_risks],
            "Risk": [f"{LEVEL_DOTS[m.level]} {LEVEL_LABELS[m.level]}" for m in result.message_risks],
            "Reasons": ["; ".join(m.reasons) or "—" for m in result.message_risks],
            "Excerpt": [m.excerpt for m in result.message_risks],
        })
        st.dataframe(risk_df, hide_index=True, use_container_width=True)

    with tabs[2]:
        if result.gaps:
            for gap in result.gaps:
                basis, rec = next((v for k, v in GAP_RECOMMENDATIONS.items() if k in gap.lower()), ("Lex Turbo Standard", "Review this gap."))
                st.markdown(f"- **{gap}** — basis: {basis}. Recommendation: {rec}")
        else:
            st.success("No material gaps detected in this synthetic log.")

    with tabs[3]:
        st.subheader("Recommended disclosure note")
        st.code(generate_disclosure_note(result.log), language="text")
        st.subheader("Recommended internal policy snippet")
        st.markdown(generate_policy_snippet(result.gaps))

    with tabs[4]:
        report = build_report(result)
        st.download_button("Download Markdown report", data=report.encode("utf-8"), file_name=f"audit_report_{Path(filename).stem}.md", mime="text/markdown", use_container_width=True)
        with st.expander("Preview report"):
            st.markdown(report)


if __name__ == "__main__":
    main()
