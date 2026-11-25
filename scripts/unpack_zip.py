#!/usr/bin/env python3
"""Unpack the files of one zip that will be uploaded to S3.

usage: unpack_zip.py <api|abi> <zip> <new destination folder> [1]       (1 = list every file)

Only for zips that passed check_zips.py. Nothing is written outside the destination folder.
  api: every file except the debug output (any folder called debug_output: logs and AST dumps)
  abi: only abi_metadata.json (the abidiff reports stay in the GitHub artifact)
Exit code 1 when the metadata file (api: metadata.json, abi: abi_metadata.json) is not in the folder afterwards.
Run it as `python3 -I -B`.
"""

import os
import sys
import zipfile

METADATA = {"api": "metadata.json", "abi": "abi_metadata.json"}


def wanted(kind, name):
    if kind == "abi":
        return name == "abi_metadata.json"
    return "debug_output" not in name.split("/")


def main(argv):
    kind, zip_path, dest = argv[1], argv[2], argv[3]
    verbose = len(argv) > 4 and argv[4] == "1"
    if kind not in METADATA:
        print("      unknown kind")
        return 1
    os.makedirs(dest)                                    # fails when the folder exists: never mix two zips
    unpacked = left_out = 0
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            if info.filename.endswith("/"):
                continue
            if not wanted(kind, info.filename):
                left_out += 1
                continue
            archive.extract(info, dest)                  # no permission bits are applied; names were checked before
            unpacked += 1
            if verbose:
                print("      unpacked %9d bytes  %s" % (info.file_size, ascii(info.filename)))
    print("      %d file(s) unpacked, %d left out (%s)" % (
        unpacked, left_out, "only abi_metadata.json is kept" if kind == "abi" else "debug_output"))
    if not os.path.isfile(os.path.join(dest, METADATA[kind])):
        print("      %s is not in the zip" % METADATA[kind])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
