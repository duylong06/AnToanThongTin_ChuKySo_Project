"""Giao diện dòng lệnh thống nhất (FR-23).

    python -m dt19 keygen   --alg ed25519
    python -m dt19 manifest --dir artifacts/
    python -m dt19 sign     --alg ed25519 artifacts/app.bin
    python -m dt19 verify   artifacts/app.bin signatures/app.bin.sig
    python -m dt19 rotate   --old <key_id> --new-alg ed25519
    python -m dt19 revoke   --key <key_id> --reason "khoa bi lo"
    python -m dt19 bench    --iterations 100 --size 1048576
"""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    """TODO(A): dựng parser với các lệnh con ở docstring trên."""
    parser = argparse.ArgumentParser(prog="dt19", description="Cong cu ky va xac minh artifact")
    parser.add_subparsers(dest="command", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    raise NotImplementedError("TODO(A): nối lệnh con vào các service")


if __name__ == "__main__":
    raise SystemExit(main())
