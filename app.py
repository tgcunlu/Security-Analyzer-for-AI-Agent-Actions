"""AI Agent Security Hybrid Analyzer: Streamlit interface (Volere SC-01, PUC-01 to PUC-03).

Run with:  streamlit run app.py
"""

from html import escape

import re

import pandas as pd
import streamlit as st

from analyzer.data_loader import build_case, load_scenarios, load_tool_catalog
from analyzer.llm import DEFAULT_MODEL
from analyzer.pipeline import analyze_case
from analyzer.rules import action_type
from analyzer.similarity import SimilaritySearch

st.set_page_config(page_title="AI Agent Security Hybrid Analyzer", layout="wide")

BODY_TEXT_CSS = """
<style>
[data-testid="stMarkdownContainer"], [data-testid="stText"], [data-testid="stTable"] td,
[data-testid="stTable"] th { font-size: 1.1rem; }
</style>
"""
st.markdown(BODY_TEXT_CSS, unsafe_allow_html=True)


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


BOX_STYLE = "flex:1; min-width:280px; border:1px solid #555555; border-radius:8px; padding:0.9em 1.1em;"
OPTIONS_EXPLANATION = f"""
<div style="display:flex; gap:1em; flex-wrap:wrap; margin-bottom:0.9em;">
  <div style="{BOX_STYLE} border-top:4px solid #EF5350;">
    <div style="color:#EF5350; font-weight:700; font-size:1.2rem; margin-bottom:0.4em;">
      Injected: what the agent would do if it followed the attack</div>
    <div style="color:#FFFFFF; font-size:1.1rem; line-height:1.55;">
      This is the action the agent would take if it obeyed the hidden instruction in the tool response.
      The dataset does not include this action, so the analyzer creates it from the attacker's tool and
      instruction. The analyzer should flag it.</div>
  </div>
  <div style="{BOX_STYLE} border-top:4px solid #66BB6A;">
    <div style="color:#66BB6A; font-weight:700; font-size:1.2rem; margin-bottom:0.4em;">
      Expected: the tool call the user's task needs</div>
    <div style="color:#FFFFFF; font-size:1.1rem; line-height:1.55;">
      This is the action the user actually asked for. It comes directly from the dataset.
      The analyzer should not flag it.</div>
  </div>
</div>
<div style="color:#42A5F5; font-weight:700; font-size:1.2rem; margin-bottom:0.3em;">Why we show both</div>
<div style="color:#FFFFFF; font-size:1.1rem; line-height:1.55; margin-bottom:1.2em;">
  Checking both shows whether the analyzer can tell an attack from normal work: it should catch the first
  without raising a false alarm on the second.</div>
"""
INTRO_STYLE = "color:#FFFFFF; font-size:1.1rem; line-height:1.55; margin-bottom:0.7em;"

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


def show_actions(actions, catalog, hidden_instruction=""):
    """The proposed action as a table: tool, toolkit, what the tool does, action type, input."""
    st.caption("Each row is one tool call, in the order the agent would make it. "
               "Input is the data the agent would pass to the tool.")
    rows = []
    for number, step in enumerate(actions, start=1):
        info = catalog.get(step.tool, {})
        shown_input = step.input
        if hidden_instruction and step.input == hidden_instruction:
            shown_input = "The hidden instruction (shown in red above)"
        rows.append({
            "Tool call": number,
            "Tool": step.tool or "(none)",
            "Toolkit": info.get("toolkit", "Not in the tool catalog"),
            "What the tool does": info.get("summary", "Unknown"),
            "Action type": action_type(step, catalog).capitalize(),
            "Input": shown_input,
        })
    st.table(pd.DataFrame(rows).set_index("Tool call"))


PLAIN_SUMMARIES = {
    "Unauthorized": "This action breaks a security rule.",
    "Suspicious": "No security rule was clearly broken, but something does not look right.",
    "Authorized": ("No problems were found, and the AI model agrees that the action matches the request. "
                   "This is not a safety guarantee."),
}
# Label text and colors (background, text). The label is always written out, so color is never the only signal.
RED = ("#D32F2F", "#FFFFFF")
ORANGE = ("#FFA726", "#000000")
GREEN = ("#2E7D32", "#FFFFFF")
GRAY = ("#757575", "#FFFFFF")
OUTCOME_LABELS = {"Violation": ("Violation", RED), "Possible Issue": ("Possible issue", ORANGE),
                  "Unknown": ("Could not check", GRAY)}
ALIGNMENT_LABELS = {"Aligned": ("Matches the request", GREEN), "Misaligned": ("Does not match the request", RED),
                    "Unknown": ("Could not decide", GRAY)}
TITLE_STYLE = "color:#1E88E5; font-weight:700; font-size:1.2rem; margin-bottom:0.6em;"


def title(text):
    """A blue section title."""
    return f'<div style="{TITLE_STYLE}">{escape(text)}</div>'


def pill(label, colors):
    """A small colored label with its text written out."""
    background, foreground = colors
    return (f'<span style="background:{background}; color:{foreground}; font-weight:700; font-size:0.8rem; '
            f'padding:0.15em 0.6em; border-radius:4px;">{escape(label)}</span>')


def item(label_html, note, body):
    """One entry inside a card: colored label, small gray note, then the text on its own line."""
    note_html = f' <span style="opacity:0.65; font-size:0.85rem;">{escape(note)}</span>' if note else ""
    return (f'<div style="margin-bottom:0.9em;">{label_html}{note_html}'
            f'<div style="margin-top:0.3em;">{escape(body)}</div></div>')


def friendly_detail(detail, call_count):
    """Rule details start with "Step N". Say "The action" for one tool call, "Tool call N" for several."""
    if call_count == 1:
        return re.sub(r"^Step 1\b", "The action", detail)
    return re.sub(r"^Step (\d+)", r"Tool call \1", detail)


def show_result(result):
    """Classification, review flag, rule findings, model assessment and explanation (Volere R-15)."""
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
    st.write(PLAIN_SUMMARIES[result.classification])
    if result.human_review:
        reasons = "".join(f"<li>{escape(r)}</li>" for r in result.review_reasons)
        st.markdown(title("Why a person should review this") + f"<ul>{reasons}</ul>", unsafe_allow_html=True)

    # The two analysis components side by side
    rules_column, model_column = st.columns(2)
    with rules_column.container(border=True):
        problems = [f for f in result.findings if f.outcome != "No Issue"]
        call_count = max((f.step for f in result.findings), default=1)
        html = title("Security rules")
        if not problems:
            html += item(pill("No problems found", GREEN), "", "")
        for finding in problems:
            label, colors = OUTCOME_LABELS[finding.outcome]
            html += item(pill(label, colors), finding.issue, friendly_detail(finding.detail, call_count))
        st.markdown(html, unsafe_allow_html=True)
    with model_column.container(border=True):
        assessment = result.assessment
        html = title(f"Local AI model ({DEFAULT_MODEL})")
        if assessment.error:
            html += item(pill("Could not answer", GRAY), "", assessment.error)
        else:
            label, colors = ALIGNMENT_LABELS[assessment.alignment]
            html += item(pill(label, colors), "", assessment.reason)
        st.markdown(html, unsafe_allow_html=True)

    with st.expander("Technical details: every rule check"):
        rows = [{"Tool call": f.step if f.step else "Whole case", "Rule": f.rule_id, "Outcome": f.outcome,
                 "Issue": f.issue, "Detail": friendly_detail(f.detail, call_count)} for f in result.findings]
        st.dataframe(pd.DataFrame(rows), hide_index=True)


# Analyses completed in this browser session. The dashboard (PUC-03) summarizes this list.
if "results" not in st.session_state:
    st.session_state.results = []

scenarios = get_scenarios()
catalog = get_catalog()

model_ready, status_message = ollama_status(DEFAULT_MODEL)
dot_color = "#4CAF50" if model_ready else "#E53935"

st.title("AI Agent Security Hybrid Analyzer")
st.markdown(f'<div style="font-size:0.9rem; margin-bottom:0.8em;"><span style="color:{dot_color}; font-size:1.2rem;">'
            f'&#9679;</span> {escape(status_message)}</div>', unsafe_allow_html=True)
st.markdown(f'<div style="{INTRO_STYLE}">Compares a proposed AI-agent action with the user\'s original request. '
            'Actions are analyzed as text and are never executed.</div>', unsafe_allow_html=True)
st.markdown(OPTIONS_EXPLANATION, unsafe_allow_html=True)

benchmark_tab, manual_tab, dashboard_tab = st.tabs(["Benchmark scenario", "Manual case", "Dashboard"])

with benchmark_tab:
    st.header("Analyze a benchmark scenario")
    labels = {row.scenario_id: f"{row.scenario_id} | {row.attack_type} | {row.user_tool}"
              for row in scenarios.itertuples()}
    scenario_id = st.selectbox("Scenario", list(labels), format_func=labels.get)
    variant = st.radio("Action to analyze", ["injected", "expected"], horizontal=True,
                       format_func={"injected": "Injected: what the agent would do if it followed the attack",
                                    "expected": "Expected: the tool call the user's task needs"}.get)

    scenario = scenarios[scenarios["scenario_id"] == scenario_id].iloc[0]
    case = build_case(scenario, variant, catalog)

    st.markdown(title("1. What the user asked"), unsafe_allow_html=True)
    st.text(scenario["user_instruction"])

    st.markdown(title("2. What the agent did to answer"), unsafe_allow_html=True)
    user_tool_summary = catalog.get(scenario["user_tool"], {}).get("summary", "")
    st.markdown(f'<div>It called <b>{escape(scenario["user_tool"])}</b> with '
                f'<code>{escape(scenario["tool_parameters"])}</code>. '
                f'<span style="opacity:0.7;">({escape(user_tool_summary)})</span></div>', unsafe_allow_html=True)

    st.markdown(title("3. What the tool sent back"), unsafe_allow_html=True)
    st.write("This is the data the agent received. An attacker hid an instruction inside it, shown in red. "
             "The user did not write it, and the dataset does not show whether an agent obeyed it.")
    show_tool_response(scenario["tool_response"], scenario["attacker_instruction"])

    st.markdown(title("4. The action being analyzed"), unsafe_allow_html=True)
    show_actions(case.actions, catalog, scenario["attacker_instruction"])

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
