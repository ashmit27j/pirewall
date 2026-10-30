"""The phase-20 evaluation paper tooling: tables and figures (critique_ml.md §10).

Phase 20 turns the numbers phase 19 already wrote - the phase-19 report
directory (`metrics.json`, `table_v.csv`, the `fig*.csv` files) plus a lab
aggregate (`lab/aggregate.py` output) - into the evaluation paper's tables
and figures (critique_ml.md §10, Tables I-VII and Figs 1-5).

`lab/paper/make_tables.py` renders the paper tables and `lab/paper/make_figures.py`
renders the figure data. Their input is only those artifacts: never raw logs, never
a hand-typed number. Output is a pure function of that input (hash-stable, no
wall-clock), and every emitted table carries the manifest hashes its numbers came
from as a footnote.

Env tags (ADDENDUM_4.md D7): a `pi-*` tag is required unless the operator passes
`--regression`, which watermarks every emitted artifact
`"REGRESSION EVIDENCE (env=<tag>) — NOT A PI RESULT"`.
"""
