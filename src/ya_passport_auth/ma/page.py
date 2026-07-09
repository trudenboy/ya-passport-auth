"""Device-code login page shared by the Music Assistant yandex providers.

The page is served from MA's own webserver during a Device Flow login: it
shows the short user code (tap/click to copy, with a ``document.execCommand``
fallback for plain-HTTP LAN deployments), a link to Yandex's verification
page, an honest countdown of the code's remaining lifetime, and terminal
states driven by the status endpoint (success / failed with a reason /
expired / session ended).

Extracted from the ``yandex_music`` provider (PRs #184/#195 of
``trudenboy/ma-provider-yandex-music``), with the optional ``context_text``
paragraph from the ``yandex_alice`` provider's page.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from string import Template
from typing import Final

__all__ = [
    "DEFAULT_PAGE_STRINGS",
    "DevicePageConfig",
    "build_device_code_page",
    "resolve_language",
]

# JS-consumed subset of the page strings; the rest is substituted server-side.
_JS_STRING_KEYS: Final = (
    "copied",
    "copy_manual",
    "hint_copy",
    "expired_title",
    "expired_text",
    "success_title",
    "success_text",
    "failed_title",
    "failed_text",
    "denied_text",
    "ended_title",
    "ended_text",
)

DEFAULT_PAGE_STRINGS: Final[dict[str, dict[str, str]]] = {
    "en": {
        "lang": "en",
        "title": "Login to Yandex",
        "context": "",
        "step_copy": "Copy the code",
        "hint_copy": "Tap the code to copy it",
        "copied": "Copied ✓",
        "copy_manual": "Automatic copy failed — select the code and copy it manually",
        "step_open": "Open the Yandex page and enter the code",
        "open_button": "Continue to Yandex",
        "expires_label": "Code expires in",
        "expired_title": "Code expired",
        "expired_text": (
            "The code is no longer valid. Return to Music Assistant and start the login again."
        ),
        "success_title": "Authorization successful",
        "success_text": "You can close this window.",
        "failed_title": "Authorization failed",
        "failed_text": "Please return to Music Assistant and try again.",
        "denied_text": "The login was denied. Return to Music Assistant and try again.",
        "ended_title": "Session ended",
        "ended_text": "This login session is no longer active. You can close this window.",
    },
    "ru": {
        "lang": "ru",
        "title": "Вход в Яндекс",
        "context": "",
        "step_copy": "Скопируйте код",
        "hint_copy": "Нажмите на код, чтобы скопировать",
        "copied": "Скопировано ✓",
        "copy_manual": "Не удалось скопировать автоматически — выделите код и скопируйте вручную",  # noqa: RUF001
        "step_open": "Откройте страницу Яндекса и введите код",
        "open_button": "Перейти на Яндекс",
        "expires_label": "Код истекает через",
        "expired_title": "Код истёк",
        "expired_text": (
            "Код больше не действует. Вернитесь в Music Assistant и начните вход заново."
        ),
        "success_title": "Авторизация выполнена",
        "success_text": "Это окно можно закрыть.",
        "failed_title": "Авторизация не удалась",
        "failed_text": "Вернитесь в Music Assistant и попробуйте ещё раз.",
        "denied_text": "Вход был отклонён. Вернитесь в Music Assistant и попробуйте ещё раз.",
        "ended_title": "Сессия завершена",
        "ended_text": "Эта сессия входа больше не активна. Это окно можно закрыть.",
    },
}


@dataclass(frozen=True, slots=True)
class DevicePageConfig:
    """Provider-specific parameters of the device-code page.

    Args:
        domain: Provider domain (e.g. ``"yandex_music"``). Used as the route
            namespace (``/<domain>/device_code/...``) and as the translation
            owner when strings are resolved through MA's translations.
        title: Page title override per language (e.g.
            ``{"en": "Login to Yandex Station", "ru": "Вход в Яндекс Станцию"}``).
            Languages absent from the mapping keep the default title.
        context_text: Optional extra paragraph per language rendered above the
            steps (e.g. yandex_alice explains the skill registration). Empty
            mapping renders no paragraph.
    """

    domain: str
    title: dict[str, str] = field(default_factory=dict)
    context_text: dict[str, str] = field(default_factory=dict)

    def strings_for(self, language: str) -> dict[str, str]:
        """Return the built-in string table for *language* with overrides applied.

        Args:
            language: ``"en"`` or ``"ru"``; unknown values fall back to English.
        """
        table = dict(DEFAULT_PAGE_STRINGS.get(language, DEFAULT_PAGE_STRINGS["en"]))
        if override := self.title.get(table["lang"]):
            table["title"] = override
        if context := self.context_text.get(table["lang"]):
            table["context"] = context
        return table


def resolve_language(locale: str | None) -> str:
    """Return the page language (``"ru"`` or ``"en"``) for an MA locale string.

    Args:
        locale: The active MA locale (e.g. ``"ru_RU"``) or None.
    """
    if isinstance(locale, str) and locale.lower().startswith("ru"):
        return "ru"
    return "en"


_PAGE_TEMPLATE: Final = Template("""<!DOCTYPE html>
<html lang="$lang">
<head>
    <meta charset="utf-8">
    <title>$title</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root { color-scheme: light dark; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0; padding: 2rem 1rem;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; box-sizing: border-box;
            background: #f5f5f7; color: #1d1d1f;
        }
        .card {
            background: #ffffff;
            border-radius: 14px; padding: 2rem;
            max-width: 28rem; width: 100%;
            box-shadow: 0 4px 20px rgba(0,0,0,.08);
            text-align: center;
        }
        h1 { margin: 0 0 1rem; font-size: 1.25rem; }
        .context { text-align: left; margin: 0 0 1rem; }
        .steps { margin: 0; padding: 0 0 0 1.4rem; text-align: left; }
        .steps li { margin: 0 0 1.25rem; }
        .steps li:last-child { margin-bottom: 0; }
        .step-label { display: block; margin-bottom: .5rem; line-height: 1.45; }
        #code {
            display: inline-block;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 2rem; font-weight: 600; letter-spacing: .15em;
            padding: .75rem 1.25rem; border-radius: 10px;
            background: #f2f2f7;
            border: 1px dashed #c8c8cd;
            cursor: pointer;
            user-select: all;
        }
        #code.copied { background: #d9f2dd; border-color: #34c759; }
        .hint { margin-top: .4rem; font-size: .85rem; color: #6e6e73; }
        .url {
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: .95rem; word-break: break-all;
            margin-bottom: .5rem;
        }
        .btn {
            display: inline-block; padding: .6rem 1.25rem;
            font-size: 1rem; font-weight: 600; text-decoration: none;
            border-radius: 10px;
            background: #ffcc00; color: #1d1d1f;
        }
        .btn:hover { background: #ffd633; }
        #timer { margin-top: 1.25rem; }
        p { margin: .5rem 0 0; color: #6e6e73; line-height: 1.45; }
        @media (prefers-color-scheme: dark) {
            body { background: #1c1c1e; color: #f2f2f7; }
            .card { background: #2c2c2e; box-shadow: 0 4px 20px rgba(0,0,0,.4); }
            #code { background: #3a3a3c; border-color: #545456; }
            #code.copied { background: #1f4526; border-color: #30d158; }
            .hint, p { color: #98989e; }
        }
    </style>
</head>
<body>
    <div class="card" id="card">
        <h1>$title</h1>
        $context_block
        <ol class="steps">
            <li>
                <span class="step-label">$step_copy</span>
                <div id="code" role="button" tabindex="0">$user_code</div>
                <div id="copy-hint" class="hint">$hint_copy</div>
            </li>
            <li>
                <span class="step-label">$step_open</span>
                <div class="url">$verification_url</div>
                <a class="btn" href="$verification_url" target="_blank"
                   rel="noopener">$open_button</a>
            </li>
        </ol>
        <div id="timer" class="hint">$expires_label <span id="countdown"></span></div>
    </div>
    <script>
        const statusUrl = $status_url_js;
        const strings = $strings_js;
        let remaining = $expires_in;
        let terminal = false;

        const card = document.getElementById('card');
        const codeElement = document.getElementById('code');
        const hintElement = document.getElementById('copy-hint');
        const countdownElement = document.getElementById('countdown');

        function showResult(title, message) {
            terminal = true;
            card.innerHTML = '<h1>' + title + '</h1><p>' + message + '</p>';
        }

        function fallbackCopy() {
            const selection = window.getSelection();
            const range = document.createRange();
            range.selectNodeContents(codeElement);
            selection.removeAllRanges();
            selection.addRange(range);
            let ok = false;
            try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
            return ok;
        }

        async function copyCode() {
            const code = codeElement.textContent.trim();
            let ok = false;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(code);
                    ok = true;
                } catch (e) { ok = false; }
            }
            if (!ok) ok = fallbackCopy();
            codeElement.classList.toggle('copied', ok);
            if (hintElement) {
                hintElement.textContent = ok ? strings.copied : strings.copy_manual;
            }
            if (ok) {
                setTimeout(() => {
                    codeElement.classList.remove('copied');
                    if (hintElement) hintElement.textContent = strings.hint_copy;
                }, 2000);
            }
        }
        if (codeElement) {
            codeElement.addEventListener('click', copyCode);
            codeElement.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copyCode(); }
            });
        }

        function renderCountdown() {
            if (!countdownElement) return;
            const m = Math.floor(remaining / 60);
            const s = String(remaining % 60).padStart(2, '0');
            countdownElement.textContent = m + ':' + s;
        }
        renderCountdown();
        const timerId = setInterval(() => {
            remaining -= 1;
            if (terminal) { clearInterval(timerId); return; }
            if (remaining <= 0) {
                clearInterval(timerId);
                showResult(strings.expired_title, strings.expired_text);
                return;
            }
            renderCountdown();
        }, 1000);

        async function pollStatus() {
            if (terminal) return;
            try {
                const r = await fetch(statusUrl, { cache: 'no-store' });
                if (r.status === 404 || r.status === 410) {
                    showResult(strings.ended_title, strings.ended_text);
                    return;
                }
                if (r.ok) {
                    const data = await r.json();
                    if (data.state === 'done') {
                        showResult(strings.success_title, strings.success_text);
                        setTimeout(() => { try { window.close(); } catch (e) {} }, 300);
                        return;
                    }
                    if (data.state === 'failed') {
                        if (data.reason === 'expired') {
                            showResult(strings.expired_title, strings.expired_text);
                        } else if (data.reason === 'denied') {
                            showResult(strings.failed_title, strings.denied_text);
                        } else {
                            showResult(strings.failed_title, strings.failed_text);
                        }
                        return;
                    }
                }
            } catch (e) { /* network hiccup — retry */ }
            setTimeout(pollStatus, 2000);
        }
        setTimeout(pollStatus, 2000);
    </script>
</body>
</html>
""")


def build_device_code_page(
    *,
    user_code: str,
    verification_url: str,
    status_url: str,
    expires_in: int,
    strings: dict[str, str],
) -> str:
    """Render the HTML page shown to the user during Device Flow login.

    Yandex's verification page does not pre-fill the code from query params,
    and the MA frontend opens auth URLs in a new tab, so the user would
    otherwise have no signal that authorization succeeded. The page polls the
    status endpoint and closes itself (or shows a terminal message) when the
    backend signals completion.

    Args:
        user_code: Short confirmation code the user enters on Yandex.
        verification_url: Yandex page where the code must be entered.
        status_url: MA-hosted endpoint the page polls for the login state.
        expires_in: Code lifetime in seconds; drives the on-page countdown.
        strings: Resolved page strings (see :class:`DevicePageConfig` and
            :func:`ya_passport_auth.ma.strings.resolve_page_strings`).
    """
    # json.dumps emits a JS string literal, but `</script>` would still break
    # out of the surrounding <script> block. Escape the slash to be safe.
    safe_status_url = json.dumps(status_url).replace("</", "<\\/")
    js_strings = {key: strings[key] for key in _JS_STRING_KEYS}
    safe_strings = json.dumps(js_strings, ensure_ascii=False).replace("</", "<\\/")
    context = strings.get("context", "")
    context_block = f'<p class="context">{html.escape(context)}</p>' if context else ""
    return _PAGE_TEMPLATE.substitute(
        lang=strings["lang"],
        title=html.escape(strings["title"]),
        context_block=context_block,
        step_copy=html.escape(strings["step_copy"]),
        hint_copy=html.escape(strings["hint_copy"]),
        step_open=html.escape(strings["step_open"]),
        open_button=html.escape(strings["open_button"]),
        expires_label=html.escape(strings["expires_label"]),
        user_code=html.escape(user_code),
        verification_url=html.escape(verification_url, quote=True),
        status_url_js=safe_status_url,
        strings_js=safe_strings,
        expires_in=str(int(expires_in)),
    )
