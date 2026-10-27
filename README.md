# AI Agent Security Hybrid Analyzer

**Author:** Tugce Unlu (individual project)
**Course:** CINF 505, Fall 2026, University at Albany

## Project Description

AI agents can call external tools such as email, smart locks, or bank accounts while working on a user's
request. Content the agent reads along the way may contain hidden instructions (indirect prompt injection)
that try to make it perform a different, unauthorized action. This project builds a prototype that analyzes
a proposed agent action and explains whether it fits what the user actually asked for.

The analyzer uses a hybrid approach. A rule-based checker looks for explicit security problems: tool use
outside the scope of the request, access to sensitive data, data transfer to external destinations, and
unrequested modifications, deletions, or permission changes. A local large language model, run through
Ollama, judges whether the action is aligned with the user's original goal. The two results are combined
into a classification of Authorized, Suspicious, or Unauthorized, and uncertain or conflicting cases are
marked "Human Review Required".

The project uses the open-source InjecAgent benchmark as its reference dataset. Users will be able to analyze
an existing benchmark scenario or enter their own case, see related benchmark examples found with TF-IDF
similarity search, and view a dashboard that summarizes the analyzed cases. The analyzer only examines text;
it never executes the proposed actions.

## Technologies

- **Python** - main programming language
- **Streamlit** - web interface
- **Pandas** - loading and organizing benchmark data
- **scikit-learn** - TF-IDF and cosine similarity search
- **Ollama** (local LLM, default model `llama3.2:3b`) - goal-alignment assessment
- **Plotly** - dashboard charts
- **pytest** - automated tests
- **Git and GitHub** - version control

## Current Status

- [x] Load InjecAgent scenarios and tool catalog
- [x] TF-IDF similarity search over benchmark attacks
- [x] Security rules: tool scope, sensitive data, external transfer, action type
- [x] Input validation
- [x] Local LLM goal-alignment check with response validation
- [ ] Decision logic (Authorized / Suspicious / Unauthorized, Human Review Required)
- [ ] Streamlit interface and dashboard
- [ ] Evaluation on prepared cases

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ollama pull llama3.2:3b
python -m pytest
```

## Dataset

The files in `data/injecagent/` come from the InjecAgent benchmark
(https://github.com/uiuc-kang-lab/InjecAgent). See `data/injecagent/LICENSE` for its license.
