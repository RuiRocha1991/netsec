from __future__ import annotations

import socket
import time
from pathlib import Path


def send_log_file(
    log_path: Path,
    host: str = "127.0.0.1",
    port: int = 5514,
    delay: float = 0.05,
) -> None:
    """Envia cada linha do ficheiro de log como datagrama UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    print(f"A enviar {len(lines)} linhas para {host}:{port}...")
    sent = 0
    for line in lines:
        if line.strip():
            sock.sendto(line.encode("utf-8"), (host, port))
            sent += 1
            time.sleep(delay)
    sock.close()
    print(f"Enviadas {sent} linhas.")


if __name__ == "__main__":
    send_log_file(Path("data/logs/test_pfsense.log"))
