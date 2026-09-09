"""The control panel's emitted JavaScript must actually parse.

Every other test of `pirewall/web/render.py` asserts on HTML structure —
that a table row exists, that a value is escaped. None of them notice if the
`<script>` block is syntactically invalid, and a browser that hits a syntax
error abandons the *whole* block. The delegated click listener is registered
at the bottom of that block, so one bad string literal near the top silently
disables every button on the page: collapse, clear view, export, approve,
reject, disable, remove, and the kill switch.

That happened. `_SCRIPT` is a normal (non-raw) triple-quoted Python string,
so a `\\n` written into the JS source becomes a *real* newline in the output,
and a raw newline inside a JavaScript string literal is a syntax error. The
fix is to write `\\\\n`; these tests are what makes the mistake loud instead
of silent.

There is no JS engine available in this environment, so rather than shell out
to one that may not exist, this scans the emitted script for the specific
structural faults that break a whole block.
"""

from datetime import UTC, datetime

import pytest

from pirewall.core.enums import EnforcementMode, FailureMode
from pirewall.core.models.status import StatusResult
from pirewall.web.render import render_core_unavailable_page, render_dashboard, render_login_page

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _status() -> StatusResult:
    return StatusResult(
        started_at=NOW,
        uptime_seconds=1.0,
        enforcement_mode=EnforcementMode.ASSISTED,
        failure_mode=FailureMode.FAIL_OPEN,
        active_rule_count=0,
        pending_approval_count=0,
        tracked_flow_count=0,
        lightgbm_loaded=True,
        isolation_forest_loaded=True,
    )


def _scripts(html: str) -> list[str]:
    blocks: list[str] = []
    cursor = 0
    while True:
        start = html.find("<script", cursor)
        if start == -1:
            return blocks
        body_start = html.index(">", start) + 1
        end = html.index("</script>", body_start)
        blocks.append(html[body_start:end])
        cursor = end


def _pages() -> list[tuple[str, str]]:
    """Every page that carries a script block."""
    return [
        ("dashboard", render_dashboard(_status(), [], [], [], [], [], None, [], [], [])),
        ("login", render_login_page()),
        ("core-unavailable", render_core_unavailable_page("core is down")),
    ]


# Parametrize over names only — passing the rendered HTML as a parameter puts
# the entire page into the test id and makes any failure unreadable.
PAGE_NAMES = [name for name, _ in _pages()]


def _page(name: str) -> str:
    return dict(_pages())[name]


# A `/` starts a regex literal (rather than division) when the last
# significant character is one of these. That is the standard heuristic, and
# it is exact for the JS this file emits — `csvField`'s `/[",\\n]/` contains
# a double quote that a scanner would otherwise read as opening a string.
_REGEX_PRECEDERS = set("(=,:[!&|?{};+-*%<>~^") | {"return", "typeof", "case", "in", "of", "new"}


def _starts_regex(js: str, index: int) -> bool:
    prefix = js[:index].rstrip()
    if not prefix:
        return True
    if prefix[-1] in _REGEX_PRECEDERS:
        return True
    word = ""
    for char in reversed(prefix):
        if char.isalpha():
            word = char + word
        else:
            break
    return word in _REGEX_PRECEDERS


def _skip_regex(js: str, index: int) -> int:
    """Index just past the regex literal starting at `index`, or `index` if unterminated."""
    cursor = index + 1
    in_class = False
    while cursor < len(js):
        char = js[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == "\n":
            return index
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            return cursor + 1
        cursor += 1
    return index


def _string_literal_faults(js: str) -> list[str]:
    """Raw newlines inside a `'`/`"` string literal, which JavaScript forbids.

    A small scanner rather than a regex: it has to respect escapes and know
    which quote opened the literal, and it must not flag a newline inside a
    template literal (where they are legal) or inside a comment.
    """
    faults: list[str] = []
    quote: str | None = None
    escaped = False
    line = 1
    index = 0
    while index < len(js):
        char = js[index]
        if char == "\n":
            if quote in {"'", '"'}:
                faults.append(f"line {line}: unterminated {quote} string literal")
                quote = None
            line += 1
            index += 1
            escaped = False
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        # Outside a string: skip comments so their contents are never scanned.
        if js.startswith("//", index):
            index = js.find("\n", index)
            if index == -1:
                break
            continue
        if js.startswith("/*", index):
            closing = js.find("*/", index + 2)
            if closing == -1:
                break
            line += js.count("\n", index, closing)
            index = closing + 2
            continue
        if char == "/" and _starts_regex(js, index):
            skipped = _skip_regex(js, index)
            if skipped > index:
                index = skipped
                continue
        if char in {"'", '"', "`"}:
            quote = char
        index += 1
    return faults


@pytest.mark.parametrize("page", PAGE_NAMES)
def test_no_javascript_string_literal_contains_a_raw_newline(page: str) -> None:
    """Regression test for the fault that silently disabled every dashboard button.

    A `\\n` in the Python source of `_SCRIPT` becomes a real newline in the
    emitted JS. Inside a string literal that is a syntax error, and a syntax
    error anywhere in the block stops the whole block executing — including
    the delegated click listener every control depends on.
    """
    for script in _scripts(_page(page)):
        faults = _string_literal_faults(script)
        assert faults == [], f"{page} page has invalid JS string literal(s): {faults}"


@pytest.mark.parametrize("page", PAGE_NAMES)
def test_javascript_brackets_balance(page: str) -> None:
    """A stray brace also takes the whole block down, and reads as "nothing works"."""
    for script in _scripts(_page(page)):
        depth = {"{": 0, "(": 0, "[": 0}
        closers = {"}": "{", ")": "(", "]": "["}
        quote: str | None = None
        escaped = False
        index = 0
        while index < len(script):
            char = script[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if script.startswith("//", index):
                newline = script.find("\n", index)
                index = len(script) if newline == -1 else newline
                continue
            if script.startswith("/*", index):
                closing = script.find("*/", index + 2)
                index = len(script) if closing == -1 else closing + 2
                continue
            if char == "/" and _starts_regex(script, index):
                skipped = _skip_regex(script, index)
                if skipped > index:
                    index = skipped
                    continue
            if char in {"'", '"', "`"}:
                quote = char
            elif char in depth:
                depth[char] += 1
            elif char in closers:
                depth[closers[char]] -= 1
                assert depth[closers[char]] >= 0, f"{page}: unbalanced {char!r}"
            index += 1
        assert all(count == 0 for count in depth.values()), f"{page}: unclosed brackets {depth}"


def test_the_delegated_click_listener_is_present() -> None:
    """Every control on the page depends on this one listener.

    The buttons carry `data-` attributes and no inline handler — deliberately,
    since `html.escape` does not make interpolation into inline JS safe — so
    if this listener is missing or unreachable, nothing on the page responds.
    """
    script = "\n".join(_scripts(_page("dashboard")))
    assert 'document.addEventListener("click"' in script
    for attribute in ("data-action", "data-toggle", "data-export", "data-clear"):
        assert f'button[{attribute}]' in script, f"no delegated handler for {attribute}"


def test_every_control_attribute_the_markup_emits_has_a_handler() -> None:
    """Markup and listener must not drift apart — a control with no handler is dead."""
    import re

    html = _page("dashboard")
    script = "\n".join(_scripts(html))
    body = html[: html.index("<script")]
    emitted = set(re.findall(r'\bdata-(action|toggle|export|clear)=', body))
    assert emitted, "expected the dashboard to emit control attributes"
    for attribute in emitted:
        assert f'button[data-{attribute}]' in script, f"markup emits data-{attribute} with no handler"
