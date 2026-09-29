"""The semgate configs the installed hooks use (read only).

`semgate feedback` without --config/--store must write the approval to the
store the hook reads, from any folder. The hooks know their config: every
installed hook command passes `--config <absolute path>` (the OpenCode
plugin has it as a constant). installed_configs() asks every host adapter
for those paths (HostAdapter.hook_configs), keeps the ones that exist and
load as a semgate.json (storepaths.load), and merges the same file seen from
several hosts into one entry.

A relative `--config` in a hook is skipped: it depends on the folder the
host starts the hook in, which is not known here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .. import storepaths
from . import ADAPTERS
from .base import HostEnv


@dataclass
class InstalledConfig:
    path: str                                   # absolute, as written in the first hook that names it
    hosts: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)   # storepaths.load() of it (paths resolved)

    def hosts_text(self) -> str:
        return " and ".join(self.hosts) if len(self.hosts) <= 2 else ", ".join(self.hosts[:-1]) + " and " + self.hosts[-1]


def _key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def installed_configs(env: HostEnv) -> List[InstalledConfig]:
    """One entry per distinct config file (resolved absolute path) that an
    installed semgate hook passes and that exists and loads. Adapter order."""
    found: Dict[str, InstalledConfig] = {}
    for adapter in ADAPTERS.values():
        try:
            paths = adapter.hook_configs(env)
        except Exception:                      # a broken hooks file of one host must not hide the others
            continue
        for raw in paths:
            path = os.path.expanduser(raw)
            if not os.path.isabs(path) or not os.path.isfile(path):
                continue
            key = _key(path)
            if key in found:
                if adapter.name not in found[key].hosts:
                    found[key].hosts.append(adapter.name)
                continue
            try:
                config = storepaths.load(path, adapter.name)
            except (OSError, ValueError, UnicodeDecodeError):
                continue
            found[key] = InstalledConfig(os.path.abspath(path), [adapter.name], config)
    return list(found.values())
