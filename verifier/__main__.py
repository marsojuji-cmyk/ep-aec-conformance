"""
__main__.py — CLI entry point for the EP-AEC conformance verifier.

Usage:
    python -m verifier verify chain.json [--policy policy.json]
    python -m verifier probe [--json output.json]
    python -m verifier vectors [--json output.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Ensure verifier/ is on sys.path for absolute imports (epaec, jcs, components)
_verifier_dir = os.path.dirname(os.path.abspath(__file__))
if _verifier_dir not in sys.path:
    sys.path.insert(0, _verifier_dir)


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a single chain against a policy."""
    from epaec import Policy, verify_chain
    from components import default_registry

    with open(args.chain) as f:
        chain = json.load(f)

    policy = Policy()
    if args.policy:
        with open(args.policy) as f:
            pdata = json.load(f)
        policy = Policy(
            requirement=pdata.get("requirement"),
            expected_effect_digest=pdata.get("expected_effect_digest"),
            pinned_executor_keys=pdata.get("pinned_executor_keys", {}),
            ceremony_min_review_sec=pdata.get("ceremony_min_review_sec"),
            authorizations=pdata.get("authorizations", {}),
            spec_revision=pdata.get("spec_revision", "02"),
        )

    result = verify_chain(chain, default_registry(), policy)
    out = result.as_dict()

    if args.json:
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print("wrote", args.json)
    else:
        print("verdict:    %s" % out["verdict"])
        print("reason:     %s" % out["reason"])
        print("source:     %s" % out.get("requirement_source", "n/a"))
        if out.get("components"):
            print("components:")
            for c in out["components"]:
                label = c.get("label", "")
                lbl = f" (label={label!r})" if label else ""
                print("  [%d] %s%s: %s — %s" % (
                    c["index"], c["type"], lbl,
                    "BOUND" if c.get("bound") else "UNBOUND",
                    c.get("reason", "")))

    return 0 if out["verdict"] == "ALLOW" else 1


def cmd_probe(args: argparse.Namespace) -> int:
    """Run adversarial probes."""
    import subprocess
    import os
    probe_path = os.path.join(os.path.dirname(__file__), "probe.py")
    cmd = [sys.executable, probe_path]
    if args.json:
        cmd.extend(["--json", args.json])
    return subprocess.call(cmd)


def cmd_vectors(args: argparse.Namespace) -> int:
    """Run conformance vectors."""
    import subprocess
    import os
    test_path = os.path.join(os.path.dirname(__file__), "..", "tests", "test_conformance.py")
    cmd = [sys.executable, "-m", "pytest", test_path, "-v"]
    if args.json:
        # run with --json for structured output
        cmd2 = [sys.executable, test_path, "--json", args.json]
        return subprocess.call(cmd2)
    return subprocess.call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ep-aec-conformance",
        description="EP-AEC conformance verifier — independent implementation of "
                    "draft-schrock-ep-authorization-evidence-chain-02",
    )
    sub = parser.add_subparsers(dest="command")

    p_verify = sub.add_parser("verify", help="Verify a single chain")
    p_verify.add_argument("chain", help="Path to chain JSON file")
    p_verify.add_argument("--policy", help="Path to policy JSON file")
    p_verify.add_argument("--json", help="Write result to JSON file")

    p_probe = sub.add_parser("probe", help="Run adversarial probes")
    p_probe.add_argument("--json", help="Write results to JSON file")

    p_vectors = sub.add_parser("vectors", help="Run conformance vectors")
    p_vectors.add_argument("--json", help="Write results to JSON file")

    args = parser.parse_args()

    if args.command == "verify":
        return cmd_verify(args)
    elif args.command == "probe":
        return cmd_probe(args)
    elif args.command == "vectors":
        return cmd_vectors(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())