"""AI Agent Security Hybrid Analyzer: Streamlit interface (Volere SC-01, PUC-01 to PUC-03).

Run with:  streamlit run app.py
"""

from html import escape

import pandas as pd
import streamlit as st

from analyzer.data_loader import build_case, load_scenarios, load_tool_catalog
from analyzer.llm import DEFAULT_MODEL
from analyzer.pipeline import analyze_case
from analyzer.similarity import SimilaritySearch

st.set_page_config(page_title="AI Agent Security Hybrid Analyzer", layout="wide")


# Loading the data takes a moment, so Streamlit keeps it in memory instead of reloading on every click.
@st.cache_data
def get_scenarios():
    return load_scenarios()


@st.cache_data
def get_catalog():
    return load_tool_catalog()


@st.cache_resource
def get_search():
    return SimilaritySearch(get_scenarios())


def ollama_status(model):
    """(True, message) if Ollama is running and the model is installed, otherwise (False, message)."""
    try:
        import ollama
        names = [m.model for m in ollama.Client(timeout=3).list().models]
    except Exception:
        return False, "Ollama is not running. Rule checks still work; the model result will be Unknown."
    if any(name.startswith(model) for name in names):
        return True, f"Ollama is running with {model}."
    return False, f"Ollama is running, but {model} is not installed. Run: ollama pull {model}"


def record_result(result, source):
    """Save a completed analysis for the dashboard. Re-analyzing the same case replaces its old entry.

    Cases that were not analyzed (invalid input) are not recorded (Volere R-16).
    """
    if not result.classification:
        return
    st.session_state.results = [r for r in st.session_state.results if r["case_id"] != result.case_id]
    st.session_state.results.append({
        "case_id": result.case_id,
        "source": source,
        "classification": result.classification,
        "human_review": result.human_review,
        "issues": result.issues,
    })


REVIEW_BADGE = ('<div style="display:inline-block; background:#FFFF00; color:#000000; font-weight:bold; '
                'padding:0.4em 1em; border-radius:6px; box-shadow:0 0 12px #FFFF00;">HUMAN REVIEW REQUIRED</div>')


def show_tool_response(tool_response, injected):
    """The tool output the agent read, with the injected instruction shown in red."""
    text = tool_response.strip().strip('"')
    before, found, after = text.partition(injected)
    if not found:  # the instruction is not inside the response: show it separately
        before, after = text + "\n\n", ""
    st.markdown(
        '<div style="font-family:monospace; white-space:pre-wrap; padding:0.75em; '
        'border:1px solid #999999; border-radius:6px;">'
        f'{escape(before)}<span style="color:#E00000; font-weight:bold;">{escape(injected)}</span>{escape(after)}'
        '</div>', unsafe_allow_html=True)


def show_actions(actions):
    """The proposed action steps as a table."""
    rows = [{"Step": number, "Tool": step.tool or "(none)", "Input": step.input}
            for number, step in enumerate(actions, start=1)]
    st.dataframe(pd.DataFrame(rows), hide_index=True)


def show_result(result):
    """Classification, review flag, issues, explanation, rule findings and model assessment (Volere R-15)."""
    st.subheader("Analysis result")
    if result.input_problems:
        st.error("Not analyzed: " + " ".join(result.input_problems))
        return

    # Classification and the review badge on one line (the badge only appears when review is required)
    badge = REVIEW_BADGE if result.human_review else ""
    st.markdown(
        '<div style="font-size:0.875rem;">Classification</div>'
        '<div style="display:flex; align-items:center; gap:1em; flex-wrap:wrap; margin-bottom:0.5em;">'
        f'<span style="font-size:2.25rem;">{escape(result.classification)}</span>{badge}</div>',
        unsafe_allow_html=True)
    if result.human_review:
        st.markdown("**Why:** " + " ".join(result.review_reasons))
    st.markdown("**Identified issues:** " + (", ".join(result.issues) if result.issues else "None"))

    st.markdown("**Explanation**")
    st.text(result.explanation)

    st.markdown("**Rule findings**")
    rows = [{"Step": f.step if f.step else "Whole case", "Rule": f.rule_id, "Outcome": f.outcome,
             "Issue": f.issue, "Detail": f.detail} for f in result.findings]
    st.dataframe(pd.DataFrame(rows), hide_index=True)

    st.markdown("**Local model assessment**")
    if result.assessment.error:
        st.write(f"Unknown. {result.assessment.error}")
    else:
        st.write(f"{result.assessment.alignment}. {result.assessment.reason}")


# Analyses completed in this browser session. The dashboard (PUC-03) summarizes this list.
if "results" not in st.session_state:
    st.session_state.results = []

scenarios = get_scenarios()
catalog = get_catalog()

st.title("AI Agent Security Hybrid Analyzer")
st.caption("Compares a proposed AI-agent action with the user's original request. "
           "Actions are analyzed as text and are never executed.")

with st.sidebar:
    st.header("Status")
    model_ready, status_message = ollama_status(DEFAULT_MODEL)
    if model_ready:
        st.success(status_message)
    else:
        st.warning(status_message)
    st.write(f"Benchmark scenarios loaded: {len(scenarios)}")
    st.write(f"Tools in catalog: {len(catalog)}")
    st.write(f"Analyses this session: {len(st.session_state.results)}")

benchmark_tab, manual_tab, dashboard_tab = st.tabs(["Benchmark scenario", "Manual case", "Dashboard"])

with benchmark_tab:
    st.header("Analyze a benchmark scenario")
    labels = {row.scenario_id: f"{row.scenario_id} | {row.attack_type} | {row.user_tool}"
              for row in scenarios.itertuples()}
    scenario_id = st.selectbox("Scenario", list(labels), format_func=labels.get)
    variant = st.radio("Action to analyze", ["injected", "expected"], horizontal=True,
                       format_func={"injected": "Injected: the action the attacker wants",
                                    "expected": "Expected: the tool call the user's task needs"}.get)

    scenario = scenarios[scenarios["scenario_id"] == scenario_id].iloc[0]
    case = build_case(scenario, variant, catalog)

    st.markdown("**Original request** (written by the user)")
    st.text(scenario["user_instruction"])
    st.markdown("**Tool response the agent read** (from the tool the user's request needs)")
    show_tool_response(scenario["tool_response"], scenario["attacker_instruction"])
    st.caption("Red text: the injected instruction hidden inside the tool response. The user did not write it. "
               "It is proposed behavior, not proof that an agent executed it.")
    st.markdown("**Proposed action being analyzed**")
    show_actions(case.actions)

    if st.button("Analyze scenario", type="primary"):
        with st.spinner("Checking rules and asking the local model..."):
            result = analyze_case(case, catalog)
        record_result(result, "Benchmark")
        st.session_state.benchmark_result = result

    last = st.session_state.get("benchmark_result")
    if last is not None and last.case_id == case.case_id:
        show_result(last)

with manual_tab:
    st.info("Manual case analysis will be added in Step 4.3.")

with dashboard_tab:
    st.info("The dashboard will be added in Step 4.4.")
