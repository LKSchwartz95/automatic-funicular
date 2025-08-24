import os
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Optional
import json
import logging

logger = logging.getLogger(__name__)


class RotatingJsonlWriter:
    def __init__(
        self,
        dir_path: str,
        rotate_minutes: int,
        rotate_max_mb: int,
        fmt: str,
    ):
        self.dir = Path(dir_path)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.rotate_minutes = rotate_minutes
        self.rotate_max_bytes = rotate_max_mb * 1024 * 1024
        self.fmt = fmt
        self._lock = threading.Lock()
        self._fp: Optional[IO] = None
        self._fp_path: Optional[Path] = None
        self._next_rotate_ts = 0
        self._current_file_size = 0

    def _new_path(self) -> Path:
        ts = datetime.now(timezone.utc).strftime(self.fmt)
        return self.dir / f"{ts}.jsonl"

    def _open_new(self):
        if self._fp:
            try:
                self._fp.flush()
                os.fsync(self._fp.fileno())
                self._fp.close()
                logger.info(f"Closed file: {self._fp_path}")
            except Exception as e:
                logger.error(f"Error closing file {self._fp_path}: {e}")

        self._fp_path = self._new_path()
        try:
            self._fp = open(self._fp_path, "a", encoding="utf-8")
            self._next_rotate_ts = time.time() + self.rotate_minutes * 60
            self._current_file_size = 0
            logger.info(f"Created new file: {self._fp_path}")
        except Exception as e:
            logger.error(f"Error creating file {self._fp_path}: {e}")
            raise

    def _should_rotate(self) -> bool:
        if not self._fp_path or not self._fp:
            return True
        if time.time() >= self._next_rotate_ts:
            return True
        if self._current_file_size >= self.rotate_max_bytes:
            return True
        return False

    def write_line(self, obj: dict):
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock:
            if self._should_rotate():
                self._open_new()
            
            try:
                self._fp.write(line + "\n")
                self._fp.flush()
                self._current_file_size += len(line) + 1
            except Exception as e:
                logger.error(f"Error writing to file {self._fp_path}: {e}")
                raise

    def get_current_file_info(self) -> Optional[dict]:
        """Get information about the current file being written to."""
        with self._lock:
            if self._fp_path and self._fp:
                return {
                    "path": str(self._fp_path),
                    "size_bytes": self._current_file_size,
                    "next_rotation": datetime.fromtimestamp(self._next_rotate_ts, tz=timezone.utc).isoformat(),
                }
        return None

    def close(self):
        with self._lock:
            if self._fp:
                try:
                    self._fp.flush()
                    os.fsync(self._fp.fileno())
                    self._fp.close()
                    self._fp = None
                    logger.info(f"Writer closed, final file: {self._fp_path}")
                except Exception as e:
                    logger.error(f"Error closing writer: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
