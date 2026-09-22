from __future__ import annotations

import logging
import signal
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.parsers.syslog_server import SyslogServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


def main() -> None:
    server = SyslogServer(host="0.0.0.0", port=5514)
    server.start()

    def _shutdown(sig: int, frame: object) -> None:
        print("\n[SyslogServer] A parar...")
        server.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
