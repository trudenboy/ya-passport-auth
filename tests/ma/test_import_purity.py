"""The core library must not depend on the MA runtime.

``import ya_passport_auth`` (and every non-``ma`` module) must work without
``music_assistant`` or even ``music_assistant_models`` installed — standalone
consumers of the auth library must not be affected by the MA layer. The
``ma`` modules themselves import only ``music_assistant_models`` at module
level; the MA *server* package is imported lazily inside the flows.
"""

from __future__ import annotations

import subprocess
import sys


def _run_isolated(code: str) -> subprocess.CompletedProcess[str]:
    # -S is not used (site-packages needed); instead the probe blocks the MA
    # modules via a meta-path hook before importing the library.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


_BLOCKER = """
import importlib.abc, sys

class _Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in {blocked!r}:
            raise ModuleNotFoundError(f"blocked: {{fullname}}")
        return None

sys.meta_path.insert(0, _Blocker())
"""


def test_core_importable_without_any_ma_packages() -> None:
    code = _BLOCKER.format(blocked=("music_assistant", "music_assistant_models")) + (
        "import ya_passport_auth\n"
        "import ya_passport_auth.client\n"
        "import ya_passport_auth.flows\n"
        "print('ok')\n"
    )
    result = _run_isolated(code)
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_ma_layer_importable_without_ma_server() -> None:
    # music_assistant_models is a declared dependency of the [ma] extra;
    # only the *server* package must stay optional at import time.
    code = _BLOCKER.format(blocked=("music_assistant",)) + (
        "import ya_passport_auth.ma\n"
        "from ya_passport_auth.ma import run_device_flow, CredentialCascade\n"
        "print('ok')\n"
    )
    result = _run_isolated(code)
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout
