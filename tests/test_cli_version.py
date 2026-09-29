"""`semgate --version` and `semgate -V` print the package version."""
import subprocess
import sys
from pathlib import Path

import pytest

from semgate import __version__
from semgate.cli import main

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_version_flag_prints_the_package_version(flag, capsys):
    with pytest.raises(SystemExit) as exc:
        main([flag])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"semgate {__version__}"


def test_version_flag_through_python_m():
    out = subprocess.run([sys.executable, "-m", "semgate", "--version"], cwd=ROOT, capture_output=True, text=True,
                         timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == f"semgate {__version__}"
