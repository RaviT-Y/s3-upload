#!/usr/bin/env python3
"""Keep only the downloaded zips that hold nothing but plain data files (the allowed extensions are an argument).

usage: check_zips.py <downloads-dir> "<allowed extensions>"      e.g.  check_zips.py work/downloads "txt json html log"

Reads <downloads-dir>/downloads.tsv   (repo, run_id, kind, artifact_id, created_at, head_sha, zip):
  - a zip that passes stays in downloads.tsv
  - a zip that fails is deleted and recorded in skipped.tsv   (repo, run_id, kind, reason)

A zip fails when it
  - is not a readable zip, is empty, has too many entries or an encrypted entry
  - has a file name that is absolute, contains "..", a backslash or a control character
  - contains anything but regular files and empty folders (symlinks, devices, a folder holding data),
    or a file with an execute permission
  - contains a file whose extension is not allowed (so no scripts, programs, libraries or archives by name)
  - contains a file that has an allowed name but is really a program, script or archive (first bytes)
Folders may be nested as deep as you like: every file down there is checked the same way.

Nothing is extracted: only the zip's directory and the first bytes of each file are read.
Run it as `python3 -I -B`.
"""

import collections
import os
import stat
import sys
import zipfile

VERBOSE = True      # testing: print every detail (every entry of every zip). Set to False for a short log.

MAX_ENTRIES = 5000
SNIFF_BYTES = 4096
PREVIEW_BYTES = 24  # verbose log: how many of the first bytes of each file are shown

# First bytes of programs, scripts and archives.
SIGNATURES = (
    (b"\x7fELF", "program"), (b"MZ", "program"), (b"\x00asm", "program"),
    (b"\xfe\xed\xfa\xce", "program"), (b"\xfe\xed\xfa\xcf", "program"),
    (b"\xce\xfa\xed\xfe", "program"), (b"\xcf\xfa\xed\xfe", "program"), (b"\xca\xfe\xba\xbe", "program"),
    (b"#!", "script"),
    (b"PK\x03\x04", "archive"), (b"PK\x05\x06", "archive"), (b"\x1f\x8b", "archive"),
    (b"\xfd7zXZ\x00", "archive"), (b"7z\xbc\xaf\x27\x1c", "archive"), (b"\x28\xb5\x2f\xfd", "archive"),
    (b"Rar!", "archive"),
)


def clean(text):
    """Text for the log: control characters are escaped, so a value can never start a workflow command."""
    return "".join(ch if ch.isprintable() or ch == "\t" else ascii(ch)[1:-1] for ch in text)


def disguised(head):
    """Reason code if the first bytes of a file are not those of a text file, else None."""
    for magic, what in SIGNATURES:
        if head.startswith(magic):
            return "disguised-" + what
    if head.startswith(b"BZh") and head[3:4].isdigit():
        return "disguised-archive"
    if b"\x00" in head:
        return "binary-content"
    return None


def check(zip_path, allowed, log=lambda text: None):
    """Return None if the zip is fine, otherwise (reason, entry name shown escaped).

    log(text) gets one detail line per entry (the entry names are escaped)."""
    try:
        archive = zipfile.ZipFile(zip_path)
    except Exception as exc:
        log("      not a readable zip (%s)" % type(exc).__name__)
        return "not-a-zip", ""
    with archive:
        infos = archive.infolist()
        log("      entries: %d" % len(infos))
        if not infos:
            return "empty-zip", ""
        if len(infos) > MAX_ENTRIES:
            log("      more than the %d entries allowed" % MAX_ENTRIES)
            return "too-many-files", str(len(infos))

        def reject(number, reason, shown):
            log("      %4d REJECTED  %s   %s" % (number, reason, shown))
            if number < len(infos):
                log("           the other %d entries were not checked" % (len(infos) - number))
            return reason, shown

        seen = set()
        files = 0
        for number, info in enumerate(infos, start=1):
            name = info.filename
            shown = ascii(name)
            if (name.startswith("/") or "\\" in name or ".." in name.split("/")
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in name)):
                return reject(number, "unsafe-path", shown)
            if info.flag_bits & 0x1:
                return reject(number, "encrypted-entry", shown)
            mode = (info.external_attr >> 16) if info.create_system == 3 else 0
            file_type = stat.S_IFMT(mode)
            if name.endswith("/"):                       # a folder entry: fine at any depth, but it must be empty
                if file_type not in (0, stat.S_IFDIR):
                    return reject(number, "not-a-regular-file", shown)
                if info.file_size:                       # data hidden in a folder entry would never be looked at
                    return reject(number, "folder-with-content", shown)
                log("      %4d folder    %s" % (number, shown))
                continue
            if file_type not in (0, stat.S_IFREG):       # symlink, device, pipe, ...
                return reject(number, "not-a-regular-file", shown)
            if mode & 0o111:
                return reject(number, "executable-file", shown)
            extension = os.path.splitext(name)[1].lower().lstrip(".")
            if extension not in allowed:
                return reject(number, "unexpected-file-type", shown)
            if name.casefold() in seen:
                return reject(number, "duplicate-file-name", shown)
            seen.add(name.casefold())
            files += 1
            try:
                with archive.open(info) as handle:
                    head = handle.read(SNIFF_BYTES)
            except Exception:
                return reject(number, "corrupt-archive", shown)
            problem = disguised(head)
            if problem:
                return reject(number, problem, shown)
            log("      %4d ok        %9d bytes  mode %-8s .%-5s  %s   starts with %s" % (
                number, info.file_size, oct(mode), extension, shown, repr(head[:PREVIEW_BYTES])))
        if files == 0:
            log("      no files in the zip, only folders")
            return "empty-zip", ""
    return None


def count_files(zip_path):
    counts = collections.Counter()
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            if not info.filename.endswith("/"):
                counts[os.path.splitext(info.filename)[1].lower() or "(none)"] += 1
    return ", ".join("%d x %s" % (n, ext) for ext, n in sorted(counts.items()))


def main(argv):
    log = print if VERBOSE else (lambda text: None)
    downloads_dir, allowed_text = argv[1], argv[2]
    allowed = {item.strip().lstrip(".").lower() for item in allowed_text.split() if item.strip()}
    if not allowed:
        print("::error::no allowed file extensions given")
        return 1
    downloads = os.path.join(downloads_dir, "downloads.tsv")
    skipped = os.path.join(downloads_dir, "skipped.tsv")

    with open(downloads, encoding="utf-8") as handle:
        rows = [line.rstrip("\n").split("\t") for line in handle if line.strip()]

    log("== settings")
    log("   allowed file types: %s" % ", ".join(sorted(allowed)))
    log("   limits: %d entries per zip, the first %d bytes of every file are inspected" % (MAX_ENTRIES, SNIFF_BYTES))
    log("   python: %s" % sys.version.split()[0])
    log("   %s: %d zip(s) to check" % (clean(downloads), len(rows)))

    kept = []
    reasons = collections.Counter()
    for row in rows:
        repo, run_id, kind, zip_path = clean(row[0]), clean(row[1]), clean(row[2]), row[6]
        log("== %s run %s %s" % (repo, run_id, kind))
        try:
            size = "%d bytes" % os.path.getsize(zip_path)
        except OSError:
            size = "file is missing"
        log("   artifact %s, created %s, commit %s" % (clean(row[3]), clean(row[4]), clean(row[5])[:12]))
        log("   zip %s, %s" % (clean(zip_path), size))
        verdict = check(zip_path, allowed, log)
        if verdict is None:
            kept.append(row)
            print("   valid    %s run %s %s: %s" % (repo, run_id, kind, count_files(zip_path)))
            continue
        reason, entry = verdict
        reasons[reason] += 1
        try:
            os.remove(zip_path)                              # only valid zips stay on disk
            os.rmdir(os.path.dirname(zip_path))
        except OSError:
            pass
        with open(skipped, "a", encoding="utf-8") as out:
            out.write("%s\t%s\t%s\t%s\n" % (repo, run_id, kind, reason))
        print("::warning::%s run %s %s skipped (%s) %s" % (repo, run_id, kind, reason, entry))

    with open(downloads, "w", encoding="utf-8") as out:
        for row in kept:
            out.write("\t".join(row) + "\n")
    print("Valid zips: %d, skipped: %d (allowed file types: %s)" % (
        len(kept), len(rows) - len(kept), ", ".join(sorted(allowed))))

    if VERBOSE:
        for reason, count in sorted(reasons.items()):
            log("   skipped because of %s: %d" % (reason, count))
        for title, path in (("downloads.tsv (the valid zips: repo, run_id, kind, artifact_id, created_at, head_sha, zip)", downloads),
                            ("skipped.tsv (everything skipped in this run so far: repo, run_id, kind, reason)", skipped)):
            log("")
            log("=== " + title)
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        log("   " + clean(line.rstrip("\n")))
            except OSError:
                log("   (missing)")
        log("=== files on disk")
        for folder, _, names in sorted(os.walk(downloads_dir)):
            for name in sorted(names):
                path = os.path.join(folder, name)
                log("   %9d bytes  %s" % (os.path.getsize(path), clean(path)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
