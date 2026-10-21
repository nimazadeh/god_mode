#!/usr/bin/env python3
"""Start one or more servers, wait for them to be ready, run a command, then clean up."""

import argparse
import socket
import subprocess
import sys
import time


def is_server_ready(port: int, timeout: int = 30) -> bool:
    """Wait for server to be ready by polling the TCP port."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Run command with one or more servers")
    parser.add_argument("--server", action="append", dest="servers", required=True)
    parser.add_argument("--port", action="append", dest="ports", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.command and args.command[0] == "--":
        args.command = args.command[1:]

    processes = []
    try:
        for cmd, port in zip(args.servers, args.ports):
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append(proc)
            if not is_server_ready(port, timeout=args.timeout):
                raise RuntimeError(f"Server failed to start on port {port}")
        result = subprocess.run(args.command)
        sys.exit(result.returncode)
    finally:
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
