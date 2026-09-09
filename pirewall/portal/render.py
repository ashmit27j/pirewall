"""HTML for the LAN captive portal (ADDENDUM_3.md C1, C4, C5).

Hand-rolled f-strings escaped with `html.escape`, matching
`pirewall/web/render.py` — no Jinja2, no template files, no static asset
pipeline, so nothing is added to CLAUDE.md's dependency list.

Every value interpolated here can originate from an untrusted LAN client (a
submitted username, a rule's reason string), so every one goes through `_e`.
Nothing is ever interpolated into an inline JS handler: the page's script
reads values from `data-` attributes on a JSON island, which is the same
lesson the control panel's audit finding recorded.
"""

import html
import json

_e = html.escape

_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f4f6f8; --fg: #16202a; --card: #ffffff; --line: #d6dee6;
  --muted: #5c6b7a; --accent: #1b6ac9; --ok: #1f7a44; --warn: #8a5a00;
  --danger: #b3261e; --danger-bg: #fdecea;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #10161c; --fg: #e6edf3; --card: #172029; --line: #2a3742;
    --muted: #9bb0c2; --accent: #5aa3f0; --ok: #4cc38a; --warn: #d9a441;
    --danger: #f2776b; --danger-bg: #34191a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center;
  justify-content: center; padding: 24px; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
.card {
  width: 100%; max-width: 420px; background: var(--card); border: 1px solid var(--line);
  border-radius: 12px; padding: 28px; box-shadow: 0 1px 3px rgba(0,0,0,.08);
}
h1 { margin: 0 0 4px; font-size: 20px; }
.sub { margin: 0 0 20px; color: var(--muted); font-size: 13px; }
label { display: block; margin: 14px 0 4px; font-size: 13px; font-weight: 600; }
input[type=text], input[type=password] {
  width: 100%; padding: 10px 12px; font-size: 15px; color: var(--fg);
  background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
}
input:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
button {
  width: 100%; margin-top: 20px; padding: 11px; font-size: 15px; font-weight: 600;
  color: #fff; background: var(--accent); border: 0; border-radius: 8px; cursor: pointer;
}
button.secondary { background: transparent; color: var(--accent); border: 1px solid var(--line); }
button:hover { filter: brightness(1.08); }
.notice { padding: 12px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; }
.notice.error { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }
.notice.warn { background: rgba(217,164,65,.14); color: var(--warn); border: 1px solid var(--warn); }
.status { display: flex; align-items: center; gap: 8px; font-weight: 600; color: var(--ok); }
.dot { width: 9px; height: 9px; border-radius: 50%; background: var(--ok); flex: none; }
.dot.bad { background: var(--danger); }
.meta { margin: 18px 0 0; padding-top: 16px; border-top: 1px solid var(--line);
        font-size: 13px; color: var(--muted); }
.meta dt { float: left; clear: left; width: 88px; }
.meta dd { margin: 0 0 6px 96px; font-variant-numeric: tabular-nums; }
.countdown {
  margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--line); text-align: center;
}
.countdown .time {
  font-size: 30px; font-weight: 700; font-variant-numeric: tabular-nums; letter-spacing: .02em;
}
.countdown .label { font-size: 12px; color: var(--muted); text-transform: uppercase;
                    letter-spacing: .06em; }
.countdown.low .time { color: var(--danger); }
.foot { margin-top: 18px; font-size: 11px; color: var(--muted); text-align: center; }
"""


def _page(title: str, body: str, script: str = "") -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{_e(title)}</title><style>{_STYLE}</style></head>"
        f"<body><main class=\"card\">{body}</main>{script}</body></html>"
    )


def _demo_banner(demo_accounts_present: bool) -> str:
    if not demo_accounts_present:
        return ""
    return (
        '<div class="notice warn"><strong>Demo accounts are active.</strong> '
        "This network is using the sample credentials published in the setup "
        "documentation. They must be removed before production use.</div>"
    )


def render_login_page(
    *,
    network_name: str,
    error: str = "",
    demo_accounts_present: bool = False,
    contact_message: str = "",
) -> str:
    """The page every unauthenticated client is held at."""
    error_html = f'<div class="notice error">{_e(error)}</div>' if error else ""
    contact = f'<p class="foot">{_e(contact_message)}</p>' if contact_message else ""
    body = (
        f"<h1>Sign in to {_e(network_name)}</h1>"
        '<p class="sub">This network requires authentication before internet access is granted.</p>'
        f"{_demo_banner(demo_accounts_present)}{error_html}"
        '<form method="post" action="/portal/login">'
        '<label for="username">Username</label>'
        '<input id="username" name="username" type="text" autocomplete="username" '
        'autocapitalize="none" autocorrect="off" spellcheck="false" required autofocus>'
        '<label for="password">Password</label>'
        '<input id="password" name="password" type="password" '
        'autocomplete="current-password" required>'
        "<button type=\"submit\">Sign in</button>"
        "</form>"
        f"{contact}"
    )
    return _page(f"Sign in — {network_name}", body)


def render_blocked_page(*, network_name: str, message: str) -> str:
    """Shown to a client the adaptive pipeline has blocked (ADDENDUM_3.md C4).

    Reachable because adaptive rules sit on the `forward` hook while the
    portal sits on `input` — the device's internet is gone but the Pi is
    still talking to it, which is the entire point.
    """
    body = (
        '<div class="status"><span class="dot bad"></span>Network access suspended</div>'
        f'<p class="sub" style="margin-top:12px">{_e(network_name)}</p>'
        f'<div class="notice error">{_e(message)}</div>'
        '<form method="get" action="/portal"><button class="secondary" type="submit">'
        "Back to sign in</button></form>"
    )
    return _page(f"Access suspended — {network_name}", body)


def render_keepalive_page(
    *,
    network_name: str,
    username: str,
    client_ip: str,
    seconds_remaining: int,
    keepalive_interval_seconds: int,
    contact_message: str = "",
) -> str:
    """The authenticated client's keepalive page, with the countdown to auto-logout."""
    # A JSON island rather than values interpolated into the script body:
    # `html.escape` does not make interpolation into JS safe, and `username`
    # is client-supplied.
    island = json.dumps(
        {
            "secondsRemaining": seconds_remaining,
            "intervalSeconds": keepalive_interval_seconds,
        }
    )
    body = (
        '<div class="status"><span class="dot" id="dot"></span>'
        '<span id="state">Authentication keepalive active</span></div>'
        f'<p class="sub" style="margin-top:12px">Connected to {_e(network_name)}.</p>'
        '<div class="notice" id="alert" hidden></div>'
        '<dl class="meta">'
        f"<dt>Signed in</dt><dd>{_e(username)}</dd>"
        f"<dt>Device</dt><dd>{_e(client_ip)}</dd>"
        "</dl>"
        '<div class="countdown" id="countdown">'
        '<div class="time" id="time">--:--</div>'
        '<div class="label">until automatic sign-out</div>'
        "</div>"
        '<form method="post" action="/portal/logout">'
        '<button class="secondary" type="submit">Sign out now</button></form>'
        f'<p class="foot">{_e(contact_message)}</p>'
    )
    script = (
        f'<script type="application/json" id="portal-data">{island}</script>'
        "<script>" + _KEEPALIVE_SCRIPT + "</script>"
    )
    return _page(f"Connected — {network_name}", body, script)


# The countdown ticks locally for smoothness but is *corrected* by every
# poll: `secondsRemaining` always comes from the server, computed from the
# session's `expires_at`. A client cannot extend its own session by holding
# a stopped clock — at worst the display is stale for one interval.
_KEEPALIVE_SCRIPT = """
(function () {
  var data = JSON.parse(document.getElementById('portal-data').textContent);
  var remaining = data.secondsRemaining;
  var interval = Math.max(5, data.intervalSeconds) * 1000;
  var timeEl = document.getElementById('time');
  var countdownEl = document.getElementById('countdown');
  var stateEl = document.getElementById('state');
  var dotEl = document.getElementById('dot');
  var alertEl = document.getElementById('alert');

  function paint() {
    var s = Math.max(0, remaining);
    var m = Math.floor(s / 60);
    var sec = s % 60;
    timeEl.textContent = m + ':' + (sec < 10 ? '0' : '') + sec;
    countdownEl.classList.toggle('low', s <= 60);
  }

  function fail(kind, message) {
    dotEl.classList.add('bad');
    stateEl.textContent = kind;
    alertEl.textContent = message;
    alertEl.className = 'notice error';
    alertEl.hidden = false;
    countdownEl.hidden = true;
  }

  function poll() {
    fetch('/portal/api/keepalive', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (state) {
        if (state.status === 'blocked') {
          fail('Network access suspended', state.message);
          return;
        }
        if (state.status !== 'authenticated') {
          window.location.href = '/portal';
          return;
        }
        remaining = state.seconds_remaining;
        paint();
      })
      .catch(function () { /* a dropped poll is not a logout; the next one decides */ });
  }

  paint();
  setInterval(function () {
    remaining -= 1;
    paint();
    if (remaining <= 0) { window.location.href = '/portal'; }
  }, 1000);
  setInterval(poll, interval);
  poll();
})();
"""
