"""constraints/typesafe.txt pins every package `semgate[typesafe]` installs.

typesafe-sdk asks for `httpx2>=2.0.0`, so a plain install takes the newest
httpx2 on install day (2.13.1, uploaded 2026-09-23 07:47 UTC, was less than
72 hours old on 2026-09-25). The constraints file keeps 2.13.0."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "constraints" / "typesafe.txt"


def _pins():
    pins = {}
    for line in FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9.]*)", line)
        assert m, f"not an exact pin: {line!r}"
        pins[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = m.group(2)
    return pins


def test_every_line_is_an_exact_pin_and_httpx2_stays_on_2_13_0():
    pins = _pins()
    assert pins["httpx2"] == "2.13.0" and pins["httpcore2"] == "2.13.0"
    text = FILE.read_text(encoding="utf-8")
    for name, version in pins.items():                      # every pin has its upload time in the header
        assert re.search(rf"^#\s+{re.escape(name)}\s+{re.escape(version)}\s+\d{{4}}-\d\d-\d\d \d\d:\d\d",
                         text, re.MULTILINE | re.IGNORECASE), name


def test_the_direct_pins_match_pyproject():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    extra = re.search(r"^typesafe = \[(.*?)\]", pyproject, re.MULTILINE).group(1)
    pins = _pins()
    for name, version in re.findall(r'"([A-Za-z0-9_.-]+)==([^"]+)"', extra):
        assert pins[name.lower()] == version, name


def test_the_readme_install_uses_the_constraints_file():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert 'pip install -e ".[typesafe]" -c constraints/typesafe.txt' in readme   # from a clone until the PyPI release


def test_every_installed_package_of_the_typesafe_tree_is_pinned():
    """Walks the installed typesafe-sdk's requirements (markers for this
    Python) and checks each package is in the file."""
    metadata = pytest.importorskip("importlib.metadata")
    requirements = pytest.importorskip("packaging.requirements")
    try:
        metadata.distribution("typesafe-sdk")
    except metadata.PackageNotFoundError:
        pytest.skip("the typesafe extra is not installed here")
    pins = _pins()
    seen, todo = set(), ["typesafe-sdk", "python-dotenv"]
    while todo:
        name = re.sub(r"[-_.]+", "-", todo.pop()).lower()
        if name in seen:
            continue
        seen.add(name)
        assert name in pins, f"{name} is installed by semgate[typesafe] but not pinned in {FILE.name}"
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        for raw in dist.requires or []:
            req = requirements.Requirement(raw)
            if req.marker is None or req.marker.evaluate({"extra": ""}):
                todo.append(req.name)
