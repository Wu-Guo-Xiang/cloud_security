from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuleHit:
    source: str            # 'hook' | 'engine'
    rule_id: str
    severity: str          # info | warn | high | critical
    matched: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class EventRecord:
    ts: str
    source_file: str
    line_no: int
    byte_offset: int
    event: str | None = None
    stage: str | None = None
    session_id: str | None = None
    tool: str | None = None
    phase: str | None = None
    action: str | None = None
    skipped_reason: str | None = None
    duration_ms: int | None = None
    user: str | None = None
    vm_hostname: str | None = None
    pid: int | None = None
    bash_command: str | None = None
    file_path: str | None = None
    url: str | None = None
    hook_match_count: int = 0
    client_id: str | None = None
    prompt_text: str | None = None
    block_reason: str | None = None
    raw: str | None = None
    hits: list[RuleHit] = field(default_factory=list)
