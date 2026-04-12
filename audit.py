from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_CODES = {
    'ALLOW',
    'DENY',
    'FALLBACK_USED',
    'INVALID_SIGNATURE',
    'EXPIRED_RECEIPT',
    'PAYLOAD_MISMATCH',
    'POLICY_REAUTH',
    'REPEATED_DENIALS',
    'DEGRADED_REASONING',
    'ACTION_MISMATCH',
    'INVALID_KEY',
    'INVALID_DECISION',
    'RECEIPT_NOT_YET_VALID',
    'INVALID_TIME_WINDOW',
}


@dataclass
class AuditLogger:
    path: Path

    def log(self, code: str, event: dict[str, Any]) -> None:
        if code not in ALLOWED_CODES:
            raise ValueError(f'unsupported audit code: {code}')
        record = {
            'ts': datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            'code': code,
            **event,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(record, sort_keys=True) + '\n')
