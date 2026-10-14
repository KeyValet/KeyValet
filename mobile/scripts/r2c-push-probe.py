#!/usr/bin/env python3
"""Run on simvito as root: one metadata-only FCM wake, no approval or credential operation."""
import argparse
import datetime
import json
import pathlib
import secrets
import sqlite3
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=pathlib.Path, required=True)
    args = parser.parse_args()
    with sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True) as db:
        phones = db.execute(
            "SELECT id,push_token FROM devices WHERE os='android' AND revoked_at IS NULL "
            "AND push_token IS NOT NULL AND EXISTS(SELECT 1 FROM account_sessions s "
            "WHERE s.device_id=devices.id AND s.exp>?)", (int(time.time()),)
        ).fetchall()
    if len(phones) != 1:
        print(json.dumps({"candidate_devices": len(phones), "sent": False}))
        return
    target, encoded = phones[0]
    token = json.loads(encoded)
    if token.get("platform") != "fcm":
        raise SystemExit("Expected FCM token; nothing sent.")
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    number = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    approval_id = ""
    for _ in range(26):
        approval_id = alphabet[number & 31] + approval_id
        number >>= 5
    payload = json.dumps({"device_push_token": token, "approval_id": approval_id,
                          "to": target, "delivery": {"mode": "silent"}}).encode()
    bearer = pathlib.Path("/etc/keyvalet-push/relay-bearer").read_text().strip()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def send(authorized):
        headers = {"Content-Type": "application/json"}
        if authorized:
            headers["Authorization"] = "Bearer " + bearer
        request = urllib.request.Request("http://127.0.0.1:8788/v1/push", payload, headers)
        try:
            with client.open(request, timeout=28) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    unauthenticated = send(False)
    if unauthenticated != 401:
        raise SystemExit("Unauthenticated request was not rejected; nothing sent with credentials.")
    status = send(True)
    print(json.dumps({"candidate_devices": 1, "unauthenticated_status": unauthenticated,
                      "authenticated_status": status, "delivery_mode": "silent",
                      "approval_record_created": False,
                      "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}))
    if status != 202:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
