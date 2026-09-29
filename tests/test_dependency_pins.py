"""pyproject.toml `dependencies` pins every package `pip install semgate` installs.

typesafe-sdk asks for `httpx2>=2.0.0`, so without a pin pip takes the newest
httpx2 on install day (2.13.1, uploaded 2026-09-23 07:47 UTC, was less than
72 hours old on 2026-09-25). The pin keeps 2.13.0. Until 0.4.0 these pins
were in constraints/typesafe.txt and users had to pass it with -c."""
import importlib.metadata as metadata
import re
from pathlib import Path

import pytest
from packaging.requirements import Requirement   # pytest depends on packaging

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INSTALL_DOCS = ("README.md", "docs/guide.md", "examples/harness/README.md", "docs/agy-1.2.8-live.md")


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _dependencies():
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        import tomllib
    except ImportError:            # Python 3.10: read the list line by line
        block = re.search(r"^dependencies = \[\r?\n(.*?)^\]", text, re.MULTILINE | re.DOTALL).group(1)
        return [m.group(2) for m in re.finditer(r"""^\s*(["'])(.+)\1,\s*$""", block, re.MULTILINE)]
    return tomllib.loads(text)["project"]["dependencies"]


def _pins():
    """{name: (version, marker)} for every entry of `dependencies`."""
    pins = {}
    for raw in _dependencies():
        req = Requirement(raw)
        specs = list(req.specifier)
        assert len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version, \
            f"not an exact pin: {raw!r}"
        assert not req.extras and req.url is None, raw
        pins[_norm(req.name)] = (specs[0].version, req.marker)
    return pins


def test_every_dependency_is_an_exact_pin_and_httpx2_stays_on_2_13_0():
    pins = _pins()
    assert len(pins) == 15
    assert pins["httpx2"][0] == "2.13.0" and pins["httpcore2"][0] == "2.13.0"
    assert pins["typesafe-sdk"][0] == "0.7.1"                 # the key-leak fix
    assert str(pins["exceptiongroup"][1]) == 'python_version < "3.11"'
    assert all(marker is None for name, (_, marker) in pins.items() if name != "exceptiongroup")
    text = PYPROJECT.read_text(encoding="utf-8")
    for name, (version, _) in pins.items():                 # every pin has its upload time in the comment above
        assert re.search(rf"^#\s+{re.escape(name)}\s+{re.escape(version)}\s+\d{{4}}-\d\d-\d\d \d\d:\d\d",
                         text, re.MULTILINE | re.IGNORECASE), name


def test_the_typesafe_extra_is_empty_and_dev_is_only_pytest():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert re.search(r"^typesafe = \[\]\s*$", text, re.MULTILINE)       # the 0.4.0 docs said semgate[typesafe]
    assert re.search(r'^dev = \["pytest==9\.1\.1"\]\s*$', text, re.MULTILINE)
    assert not (ROOT / "constraints" / "typesafe.txt").exists()


@pytest.mark.parametrize("doc", INSTALL_DOCS)
def test_the_install_lines_need_no_extra_and_no_constraints_file(doc):
    text = (ROOT / doc).read_text(encoding="utf-8")
    assert "constraints/typesafe" not in text
    installs = [line for line in text.splitlines() if re.search(r"pip install\b", line)]
    assert installs, doc
    for line in installs:
        if "the extra is now empty" in line:
            continue                                         # the README note about the empty extra
        assert "[typesafe]" not in line, line
    if doc == "README.md":                                    # the short README: one plain line
        assert re.search(r"^pip install semgate\s*$", text, re.MULTILINE)
    if doc == "docs/guide.md":                                # the full guide also has the clone install
        assert re.search(r"^pip install semgate\b", text, re.MULTILINE) and 'pip install -e ".[dev]"' in text


def test_every_installed_package_of_the_judge_tree_is_pinned():
    """Walks the installed requirements of every pin (markers for this
    Python): each package is pinned, and at the version installed here."""
    try:
        metadata.distribution("typesafe-sdk")
    except metadata.PackageNotFoundError:
        pytest.skip("typesafe-sdk is not installed here")
    pins = _pins()
    seen = set()
    todo = [name for name, (_, marker) in pins.items() if marker is None or marker.evaluate()]
    while todo:
        name = _norm(todo.pop())
        if name in seen:
            continue
        seen.add(name)
        assert name in pins, f"{name} is installed by semgate but has no exact pin in pyproject.toml dependencies"
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            pytest.fail(f"{name} is pinned in pyproject.toml but not installed here")
        assert dist.version == pins[name][0], f"{name}: installed {dist.version}, pinned {pins[name][0]}"
        for raw in dist.requires or []:
            req = Requirement(raw)
            if req.marker is None or req.marker.evaluate({"extra": ""}):
                todo.append(req.name)
