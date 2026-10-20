"""Giao diện dòng lệnh thống nhất (FR-23).

    python -m dt19 init
    python -m dt19 keygen   --alg ed25519 --owner "Nguyen Duy Long"
    python -m dt19 keys
    python -m dt19 manifest --dir artifacts --out artifacts/manifest.json
    python -m dt19 sign     --key <key_id> artifacts/app.bin
    python -m dt19 verify   artifacts/app.bin --sig <signature_id>
    python -m dt19 rotate   --old <key_id> --new <key_id>
    python -m dt19 revoke   --key <key_id> --reason "khoa bi lo"
    python -m dt19 affected --key <key_id>
    python -m dt19 bench    --iterations 100 --size 1048576
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .models import Manifest, sha256_file
from .repository import SqliteRepository
from .services import (
    BenchmarkRunner,
    RevocationService,
    SigningService,
    TimestampService,
    VerificationService,
)
from .signers import SignerFactory
from .trust import KeyRotationService, TrustList

DB = "data/sigtool.db"
KEYS = "keys"


def _repo() -> SqliteRepository:
    repo = SqliteRepository(DB)
    if not Path(DB).exists():
        repo.init_schema()
    return repo


def _trust_list() -> TrustList:
    tl = TrustList.latest_in(KEYS)
    if tl is None:
        print("Chua co trust list. Chay 'keygen' truoc.", file=sys.stderr)
        raise SystemExit(2)
    return tl


def cmd_init(args) -> int:
    repo = SqliteRepository(DB)
    repo.init_schema()
    print(f"Da tao co so du lieu tai {DB}")
    return 0


def cmd_keygen(args) -> int:
    repo = _repo()
    signer = SignerFactory.create(args.alg)
    key = signer.generate_key(keys_dir=KEYS, owner=args.owner)
    repo.save_key(key)

    rotation = KeyRotationService(KEYS)
    tl = TrustList.latest_in(KEYS)
    if tl is None:
        tl = rotation.publish_initial(key.key_id, key.created_at)
    else:
        from .trust import TrustEntry

        tl.add(TrustEntry(key_id=key.key_id, valid_from=key.created_at))
        tl.save(Path(KEYS) / f"trust_list_v{tl.version}.json")

    print(f"Da sinh khoa {key.key_id} ({key.alg.value})")
    print(f"  Dau van tay : {key.fingerprint}")
    print(f"  Khoa rieng  : {key.private_key_path}")
    print(f"  Trust list  : phien ban {tl.version}")
    return 0


def cmd_keys(args) -> int:
    for k in _repo().list_keys():
        print(f"{k.key_id}  {k.alg.value:14s}  {k.status:8s}  {k.owner or ''}")
    return 0


def cmd_manifest(args) -> int:
    m = Manifest(manifest_id=args.name, version=args.version)
    for p in sorted(Path(args.dir).glob("*")):
        if p.is_file() and p.name != Path(args.out).name:
            m.add_file(p)
    m.save(args.out)
    print(f"Da tao manifest {args.out} voi {len(m.entries)} muc")
    for e in m.entries:
        print(f"  {e.path:24s} {e.sha256_at_time[:16]}... {e.size_at_time} byte")
    return 0


def cmd_sign(args) -> int:
    repo = _repo()
    service = SigningService(repo)
    if args.target.endswith(".json") and args.manifest:
        m = Manifest.load(args.target)
        sig = service.sign_manifest(m, args.key)
        m.save(args.target)
    else:
        sig = service.sign_artifact(args.target, args.key)
    print(f"Da ky {args.target}")
    print(f"  Ma chu ky  : {sig.signature_id}")
    print(f"  Thuat toan : {sig.alg.value}")
    print(f"  Kich thuoc : {sig.sig_size_bytes} byte")
    print(f"  Tep chu ky : {sig.sig_path}")
    return 0


def cmd_verify(args) -> int:
    repo = _repo()
    sig = repo.get_signature(args.sig)
    if sig is None:
        print(f"Khong tim thay chu ky {args.sig}", file=sys.stderr)
        return 2

    service = VerificationService(repo, _trust_list(), verifier=args.verifier)
    if sig.target_kind == "manifest":
        m = Manifest.load(args.target)
        result = service.verify_manifest(m, sig, Path(args.target).parent)
    else:
        result = service.verify_artifact(args.target, sig)

    mark = "DAT" if result.passed else "KHONG DAT"
    print(f"[{mark}] {result.reason.value} - {result.message_vi}")
    print(f"  Thoi gian: {result.duration_ms:.3f} ms")
    return 0 if result.passed else 1


def cmd_rotate(args) -> int:
    now = datetime.now()
    tl = KeyRotationService(KEYS, overlap_days=args.overlap_days).rotate(
        args.old, args.new, now
    )
    print(f"Da phat hanh trust list phien ban {tl.version}")
    print(f"  Khoa cu {args.old} con hieu luc them {args.overlap_days} ngay")
    print(f"  Khoa moi {args.new} hieu luc tu bay gio")
    return 0


def cmd_revoke(args) -> int:
    repo = _repo()
    now = datetime.now()
    since = datetime.fromisoformat(args.since) if args.since else None
    n = RevocationService(repo).revoke(args.key, args.reason, now, since)
    KeyRotationService(KEYS).revoke_in_trust_list(args.key, since or now, now)
    print(f"Da thu hoi khoa {args.key}. So chu ky bi anh huong: {n}")
    if since is None:
        print("  (khong biet moc bi lo -> coi moi chu ky deu dang ngo)")
    print("Buoc tiep theo: xem docs/06-runbook-khoa-bi-lo.md")
    return 0


def cmd_affected(args) -> int:
    for s in RevocationService(_repo()).list_affected(args.key):
        print(f"{s.signed_at:%Y-%m-%d %H:%M}  {s.target_kind:9s}  {s.target_id}")
    return 0


def cmd_bench(args) -> int:
    runner = BenchmarkRunner(iterations=args.iterations)
    rows = runner.run(payload_size=args.size)
    runner.export_csv(rows, args.out)
    print(f"Da ghi {len(rows)} dong vao {args.out}\n")
    print(f"{'Thuat toan':16s} {'Thao tac':8s} {'Trung vi (ms)':>14s} {'p95 (ms)':>10s} {'Chu ky (B)':>11s}")
    for s in runner.summarize(rows):
        print(
            f"{s['alg']:16s} {s['thao_tac']:8s} {s['trung_vi_ms']:14.4f} "
            f"{s['p95_ms']:10.4f} {s['kich_thuoc_chu_ky_byte']:11d}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dt19", description="Cong cu ky va xac minh artifact - De tai 19"
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Tao co so du lieu").set_defaults(func=cmd_init)

    g = sub.add_parser("keygen", help="Sinh cap khoa moi")
    g.add_argument("--alg", required=True, choices=[a.value for a in SignerFactory.all_algorithms()])
    g.add_argument("--owner", default=None)
    g.set_defaults(func=cmd_keygen)

    sub.add_parser("keys", help="Liet ke khoa").set_defaults(func=cmd_keys)

    m = sub.add_parser("manifest", help="Tao manifest cho mot thu muc")
    m.add_argument("--dir", default="artifacts")
    m.add_argument("--out", default="artifacts/manifest.json")
    m.add_argument("--name", default="dt19-release")
    m.add_argument("--version", type=int, default=1)
    m.set_defaults(func=cmd_manifest)

    s = sub.add_parser("sign", help="Ky artifact hoac manifest")
    s.add_argument("target")
    s.add_argument("--key", required=True)
    s.add_argument("--manifest", action="store_true", help="Coi target la manifest")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="Xac minh chu ky")
    v.add_argument("target")
    v.add_argument("--sig", required=True, help="Ma chu ky")
    v.add_argument("--verifier", default=None)
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("rotate", help="Luan chuyen khoa")
    r.add_argument("--old", required=True)
    r.add_argument("--new", required=True)
    r.add_argument("--overlap-days", type=int, default=14)
    r.set_defaults(func=cmd_rotate)

    rv = sub.add_parser("revoke", help="Thu hoi khoa")
    rv.add_argument("--key", required=True)
    rv.add_argument("--reason", default="khoa bi lo")
    rv.add_argument(
        "--since",
        default=None,
        help="Thoi diem nghi ngo bi lo, dang ISO. Bo trong = coi moi chu ky dang ngo",
    )
    rv.set_defaults(func=cmd_revoke)

    a = sub.add_parser("affected", help="Liet ke artifact da ky bang mot khoa")
    a.add_argument("--key", required=True)
    a.set_defaults(func=cmd_affected)

    b = sub.add_parser("bench", help="Do hieu nang ba thuat toan")
    b.add_argument("--iterations", type=int, default=100)
    b.add_argument("--size", type=int, default=1024 * 1024)
    b.add_argument("--out", default="results/bench.csv")
    b.set_defaults(func=cmd_bench)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
