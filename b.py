#!/usr/bin/env python3
import sys, os
from b2sdk.v2 import B2Api, InMemoryAccountInfo

def _api():
    info = InMemoryAccountInfo()
    b2 = B2Api(info)
    b2.authorize_account("production", os.environ["B2_KEY_ID"], os.environ["B2_APP_KEY"])
    return b2

def _bucket():
    return _api().get_bucket_by_name(os.environ["B2_BUCKET"])

def ls(prefix=""):
    for f, _ in _bucket().ls(recursive=True, folder=prefix):
        print(f"{f.size:>12}  {f.file_name}")

def get(remote, local):
    _bucket().download_file_by_name(remote).save_to(local)
    print(f"GET {remote} -> {local}  ({os.path.getsize(local)} bytes)")

def put(local, remote):
    _bucket().upload_local_file(local_path=local, remote_path=remote)
    print(f"PUT {local} -> {remote}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "ls"
    if cmd == "ls":
        ls(sys.argv[2] if len(sys.argv) > 2 else "")
    elif cmd == "get":
        get(sys.argv[2], sys.argv[3])
    elif cmd == "put":
        put(sys.argv[2], sys.argv[3])
    else:
        print(f"usage: {sys.argv[0]} [ls [prefix] | get <remote> <local> | put <local> <remote>]")
        sys.exit(1)
