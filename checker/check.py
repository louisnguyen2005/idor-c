#!/usr/bin/env python3
"""Checker HTTP cục bộ cho Meko Boutique: kiểm tra health và năm ô flag theo đội.

Ví dụ:
  python3 check.py http://10.90.0.11 --key KEY --team team1
  python3 check.py http://10.90.0.11 --key KEY --team team1 --task sqli
  python3 check.py http://10.90.0.11 --key KEY --team team1 --task sqli --put FLAG{...}
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

TASKS = ("sqli", "idor", "upload", "jwt", "backup")


def call(base, key, task=None, method="GET", flag=None):
    path = "/health" if task is None else f"/api/checker/flag/{task}"
    data = None if flag is None else json.dumps({"flag": flag}).encode()
    headers = {"X-Checker-Key": key}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base.rstrip("/") + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.loads(response.read())


def main():
    parser = argparse.ArgumentParser(description="Meko Boutique service checker")
    parser.add_argument("url")
    parser.add_argument("--key", required=True)
    parser.add_argument("--team", required=True)
    parser.add_argument("--task", choices=TASKS)
    parser.add_argument("--put")
    args = parser.parse_args()
    try:
        health = call(args.url, args.key)
        if health.get("status") != "ok" or health.get("team") != args.team:
            raise RuntimeError("health/team mismatch")
        print(json.dumps({"health": "ok", "team": health["team"], "tick": health["tick"]}))
        if args.task:
            result = call(args.url, args.key, args.task, "PUT" if args.put else "GET", args.put)
            print(json.dumps(result))
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        print(f"checker error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
