"""Tests for scripts/check_zips.py: only zips that hold nothing but txt/json/html files stay."""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "check_zips.py")
ALLOWED = "txt json html"


def make_zip(path, entries, flag_bits=None):
    """entries: [(name, data, unix_mode)]; mode None = a plain file (0o644)."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 20, 10, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100644 if mode is None else mode) << 16
            archive.writestr(info, data)
    if flag_bits:                                    # zipfile resets flag bits, so patch the central directory
        with zipfile.ZipFile(path) as archive:
            start = archive.start_dir
        with open(path, "r+b") as handle:
            blob = bytearray(handle.read())
            pos = start
            while blob[pos:pos + 4] == b"PK\x01\x02":
                name_len, extra_len, comment_len = struct.unpack("<HHH", blob[pos + 28:pos + 34])
                current = struct.unpack("<H", blob[pos + 8:pos + 10])[0]
                blob[pos + 8:pos + 10] = struct.pack("<H", current | flag_bits)
                pos += 46 + name_len + extra_len + comment_len
            handle.seek(0)
            handle.write(blob)


GOOD = [("metadata.json", b'{"a": 1}', None), ("others.txt", b"[OK]x.h\n", None),
        ("hdr/armor_reports/html_reports/r.html", b"<html></html>", None), ("hdr/", b"", 0o40755)]

CASES = {
    # name: (entries, expected reason or None for "valid")
    "valid": (GOOD, None),
    "upper case extensions": ([("A.TXT", b"x", None), ("metadata.json", b"{}", None), ("C.Html", b"<p>", None)], None),
    "log file": (GOOD + [("hdr/debug_output/logs/diagnostics.log", b"log\n", None)], "unexpected-file-type"),
    "script by name": (GOOD + [("run.sh", b"echo hi\n", None)], "unexpected-file-type"),
    "program by name": (GOOD + [("tool.exe", b"MZ....", None)], "unexpected-file-type"),
    "library by name": (GOOD + [("lib.so", b"x", None)], "unexpected-file-type"),
    "archive by name": (GOOD + [("more.zip", b"x", None)], "unexpected-file-type"),
    "no extension": (GOOD + [("README", b"x", None)], "unexpected-file-type"),
    "hidden file without name": (GOOD + [(".txt", b"x", None)], "unexpected-file-type"),
    "double extension": (GOOD + [("a.txt.exe", b"x", None)], "unexpected-file-type"),
    "program renamed to txt": (GOOD + [("r.txt", b"\x7fELF\x02\x01\x01", None)], "disguised-program"),
    "windows program renamed": (GOOD + [("r.json", b"MZ\x90\x00", None)], "disguised-program"),
    "script renamed to txt": (GOOD + [("r.txt", b"#!/bin/sh\necho owned\n", None)], "disguised-script"),
    "zip renamed to html": (GOOD + [("r.html", b"PK\x03\x04rest", None)], "disguised-archive"),
    "gzip renamed to txt": (GOOD + [("r.txt", b"\x1f\x8b\x08\x00", None)], "disguised-archive"),
    "binary data in txt": (GOOD + [("r.txt", b"abc\x00\x01\x02def", None)], "binary-content"),
    "symlink": (GOOD + [("link.txt", b"/etc/passwd", 0o120777)], "not-a-regular-file"),
    "device": (GOOD + [("dev.txt", b"", 0o020666)], "not-a-regular-file"),
    "executable bit": (GOOD + [("run.txt", b"echo", 0o100755)], "executable-file"),
    "path traversal": (GOOD + [("../evil.txt", b"x", None)], "unsafe-path"),
    "deep path traversal": (GOOD + [("a/../../evil.txt", b"x", None)], "unsafe-path"),
    "absolute path": (GOOD + [("/tmp/evil.txt", b"x", None)], "unsafe-path"),
    "backslash path": (GOOD + [("a\\b.txt", b"x", None)], "unsafe-path"),
    "control character in name": (GOOD + [("x\n::error::boom.txt", b"x", None)], "unsafe-path"),
    "duplicate names": (GOOD + [("METADATA.json", b"{}", None)], "duplicate-file-name"),
    "empty zip": ([], "empty-zip"),
    "only a folder": ([("hdr/", b"", 0o40755)], "empty-zip"),
    # Folders are fine at any depth; every file down there must be valid too.
    "deep folders with valid files": (
        [("a/", b"", 0o40755), ("a/b/", b"", 0o40755), ("a/b/c/", b"", 0o40755), ("a/b/c/d/", b"", 0o40755),
         ("a/b/c/d/e.json", b"{}", None), ("a/b/x.txt", b"x", None), ("a/empty/", b"", 0o40755),
         ("metadata.json", b"{}", None)], None),
    "deep file without folder entries": ([("a/b/c/d/e/f/g.html", b"<p>", None), ("metadata.json", b"{}", None)], None),
    "folder named like a script": (GOOD + [("tools.sh/", b"", 0o40755), ("tools.sh/out.txt", b"x", None)], None),
    "bad extension deep down": (GOOD + [("a/b/c/d/e/run.sh", b"echo", None)], "unexpected-file-type"),
    "no extension deep down": (GOOD + [("a/b/c/d/README", b"x", None)], "unexpected-file-type"),
    "program renamed deep down": (GOOD + [("a/b/c/d/r.txt", b"\x7fELF\x02\x01", None)], "disguised-program"),
    "executable deep down": (GOOD + [("a/b/c/d/r.txt", b"echo", 0o100755)], "executable-file"),
    "symlink deep down": (GOOD + [("a/b/c/d/link.txt", b"/etc/passwd", 0o120777)], "not-a-regular-file"),
    "symlink named like a folder": (GOOD + [("a/b/link/", b"/etc", 0o120777)], "not-a-regular-file"),
    "data hidden in a folder entry": (GOOD + [("a/b/", b"hidden bytes", 0o40755)], "folder-with-content"),
}


class CheckZipsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "downloads")
        os.makedirs(self.dir)

    def add(self, run_id, build, kind="api", created="2026-11-20T10:00:00Z"):
        folder = os.path.join(self.dir, "o__r__%s" % run_id)
        os.makedirs(folder)
        zip_path = os.path.join(folder, kind + ".zip")
        build(zip_path)
        with open(os.path.join(self.dir, "downloads.tsv"), "a") as handle:
            handle.write("\t".join(["o/r", str(run_id), kind, "1", created, "a" * 40, zip_path]) + "\n")
        return zip_path

    def run_check(self, allowed=ALLOWED):
        open(os.path.join(self.dir, "skipped.tsv"), "a").close()
        proc = subprocess.run([sys.executable, "-I", "-B", SCRIPT, self.dir, allowed], capture_output=True, text=True,
                              env=dict(os.environ, S3_BUCKET="the-bucket"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        with open(os.path.join(self.dir, "downloads.tsv")) as handle:
            kept = [line.split("\t")[1] for line in handle]
        with open(os.path.join(self.dir, "skipped.tsv")) as handle:
            skipped = {line.split("\t")[1]: line.rstrip("\n").split("\t")[3] for line in handle}
        return kept, skipped, proc.stdout

    def test_every_case(self):
        ids = {}
        for number, (name, (entries, expected)) in enumerate(CASES.items(), start=1):
            ids[str(number)] = (name, expected)
            self.add(number, lambda path, e=entries: make_zip(path, e))
        kept, skipped, _ = self.run_check()
        for run_id, (name, expected) in ids.items():
            if expected is None:
                self.assertIn(run_id, kept, name)
                self.assertNotIn(run_id, skipped, name)
            else:
                self.assertNotIn(run_id, kept, name)
                self.assertEqual(skipped.get(run_id), expected, name)

    def test_not_a_zip_and_encrypted(self):
        def junk(path):
            with open(path, "wb") as handle:
                handle.write(b"this is not a zip at all")
        self.add(1, junk)
        self.add(2, lambda path: make_zip(path, GOOD, flag_bits=0x1))
        self.add(3, lambda path: make_zip(path, GOOD))
        kept, skipped, _ = self.run_check()
        self.assertEqual((kept, skipped), (["3"], {"1": "not-a-zip", "2": "encrypted-entry"}))

    def test_failed_zips_are_deleted_and_valid_ones_stay(self):
        good = self.add(1, lambda path: make_zip(path, GOOD))
        bad = self.add(2, lambda path: make_zip(path, GOOD + [("run.sh", b"x", None)]))
        self.run_check()
        self.assertTrue(os.path.exists(good))
        self.assertFalse(os.path.exists(bad))
        self.assertFalse(os.path.exists(os.path.dirname(bad)))

    def test_allowed_list_is_a_setting(self):
        self.add(1, lambda path: make_zip(path, GOOD + [("d.log", b"log\n", None)]))
        kept, skipped, _ = self.run_check(allowed="txt json html")
        self.assertEqual((kept, skipped), ([], {"1": "unexpected-file-type"}))
        self.add(2, lambda path: make_zip(path, GOOD + [("d.log", b"log\n", None)]))
        open(os.path.join(self.dir, "downloads.tsv"), "w").close()
        self.add(3, lambda path: make_zip(path, GOOD + [("d.log", b"log\n", None)]))
        kept, _, _ = self.run_check(allowed="txt json html log")
        self.assertEqual(kept, ["3"])

    def test_log_never_starts_a_line_with_a_workflow_command(self):
        self.add(1, lambda path: make_zip(path, GOOD + [("x\n::error::boom.txt", b"x", None)]))
        self.add(2, lambda path: make_zip(path, GOOD + [("::error::boom.sh", b"x", None)]))
        _, _, output = self.run_check()
        for line in output.splitlines():
            if line.startswith("::"):
                self.assertTrue(line.startswith("::warning::"), line)

    def test_verbose_log_shows_every_entry(self):
        self.add(1, lambda path: make_zip(path, GOOD))
        self.add(2, lambda path: make_zip(path, GOOD + [("a/b/run.sh", b"echo", None), ("late.txt", b"x", None)]))
        _, _, output = self.run_check()
        for expected in ("== settings", "allowed file types: html, json, txt",
                         "== o/r run 1 api", "== o/r run 2 api", "entries: 4", "entries: 6",
                         "folder    'hdr/'",
                         "ok  ", "'metadata.json'", "starts with b'{\"a\": 1}'",
                         "REJECTED  unexpected-file-type   'a/b/run.sh'",
                         "the other 1 entries were not checked",
                         "skipped because of unexpected-file-type: 1",
                         "=== downloads.tsv", "=== skipped.tsv", "=== files on disk",
                         "Valid zips: 1, skipped: 1"):
            self.assertIn(expected, output)

    def test_verbose_log_does_not_let_a_zip_write_workflow_commands(self):
        self.add(1, lambda path: make_zip(path, [("ok.txt", b"\r::error::boom\n::error::more", None),
                                                 ("x\r::error::boom.txt", b"x", None)]))
        _, _, output = self.run_check()
        self.assertNotIn("\r", output)
        for line in output.splitlines():
            if line.startswith("::"):
                self.assertTrue(line.startswith("::warning::"), line)

    def test_short_log(self):
        self.add(1, lambda path: make_zip(path, GOOD))
        self.add(2, lambda path: make_zip(path, GOOD + [("run.sh", b"x", None)]))
        open(os.path.join(self.dir, "skipped.tsv"), "a").close()
        code = ("import sys; sys.path.insert(0, %r); import check_zips; check_zips.VERBOSE = False; "
                "sys.exit(check_zips.main(['check_zips', %r, %r]))" % (os.path.dirname(SCRIPT), self.dir, ALLOWED))
        proc = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        # the short log: one line per zip, the summary, and the S3 paths (always printed)
        self.assertEqual([line.split()[0] for line in proc.stdout.splitlines() if line.strip()],
                         ["valid", "::warning::o/r", "Valid", "===", "api"])

    def metadata_zip(self, metadata, kind="api", name=None):
        data = metadata if isinstance(metadata, bytes) else json.dumps(metadata).encode()
        return lambda path: make_zip(path, [(name or ("metadata.json" if kind == "api" else "abi_metadata.json"), data, None),
                                            ("others.txt", b"x", None)])

    def rows(self):
        with open(os.path.join(self.dir, "downloads.tsv")) as handle:
            return [line.rstrip("\n").split("\t") for line in handle]

    def test_s3_path_is_added_to_every_valid_zip_and_logged_at_the_end(self):
        self.add(1, self.metadata_zip({"ref_name": "42/merge"}), created="2026-11-23T10:06:25Z")
        self.add(2, self.metadata_zip({"ref_name": "development"}, "abi"), kind="abi", created="2027-01-02T03:59:59Z")
        kept, skipped, output = self.run_check()
        self.assertEqual((kept, skipped), (["1", "2"], {}))
        self.assertEqual([row[7] for row in self.rows()], [
            "2026/11/23/10/github.com/o/r/42/merge/1", "2027/01/02/03/github.com/o/r/development/2"])
        end = output[output.index("=== S3 paths"):]
        self.assertIn("   api s3://the-bucket/2026/11/23/10/github.com/o/r/42/merge/1/files/", end)
        self.assertIn("   abi s3://the-bucket/2027/01/02/03/github.com/o/r/development/2/files/", end)

    def test_testing_default_ref_when_there_is_no_ref_name(self):
        self.add(1, self.metadata_zip({"pr_number": 42}))
        self.add(2, self.metadata_zip({"ref_name": None}))
        kept, skipped, output = self.run_check()
        self.assertEqual((kept, skipped), (["1", "2"], {}))
        self.assertEqual([row[7] for row in self.rows()], ["2026/11/20/10/github.com/o/r/ref-name-missing/1",
                                                           "2026/11/20/10/github.com/o/r/ref-name-missing/2"])
        self.assertIn("no ref_name in metadata.json: using the testing default 'ref-name-missing'", output)

    def test_zips_whose_s3_path_cannot_be_worked_out_are_skipped(self):
        bad_refs = ["feature/x+y", "../x", "a/../b", "a..b", "a b", "/abs", "trailing/", "a//b", ".hidden", "x/.", "ünï",
                    "a;b", "$(x)", "x\ny", "42/merge\n", "", 7, True, ["a"], {"a": 1}]
        for number, ref in enumerate(bad_refs, start=1):
            self.add(number, self.metadata_zip({"ref_name": ref}))
        n = len(bad_refs)
        self.add(n + 1, self.metadata_zip(b"this is not json"))
        self.add(n + 2, self.metadata_zip(b"[1, 2]"))
        self.add(n + 3, self.metadata_zip(b"\xff\xfe"))
        self.add(n + 4, lambda path: make_zip(path, [("others.txt", b"x", None)]))                  # no metadata file
        self.add(n + 5, self.metadata_zip({"ref_name": "x"}, name="abi_metadata.json"))             # api needs metadata.json
        self.add(n + 6, self.metadata_zip({"ref_name": "x"}, kind="abi", name="metadata.json"), kind="abi")
        self.add(n + 7, self.metadata_zip({"ref_name": "x"}), created="yesterday")
        kept, skipped, output = self.run_check()
        self.assertEqual(kept, [])
        self.assertEqual({int(k): v for k, v in skipped.items()}, dict(
            [(number, "invalid-ref") for number in range(1, n + 1)] +
            [(n + 1, "invalid-metadata"), (n + 2, "invalid-metadata"), (n + 3, "invalid-metadata"),
             (n + 4, "no-metadata"), (n + 5, "no-metadata"), (n + 6, "no-metadata"), (n + 7, "unexpected-data")]))
        self.assertEqual(self.rows(), [])
        for line in output.splitlines():
            if line.startswith("::"):
                self.assertTrue(line.startswith("::warning::"), line)

    def test_huge_metadata_file_is_refused(self):
        self.add(1, self.metadata_zip(b'{"ref_name": "x", "pad": "' + b"a" * 2_000_000 + b'"}'))
        self.assertEqual(self.run_check()[:2], ([], {"1": "invalid-metadata"}))

    def test_empty_list(self):
        open(os.path.join(self.dir, "downloads.tsv"), "w").close()
        kept, skipped, output = self.run_check()
        self.assertEqual((kept, skipped), ([], {}))
        self.assertIn("Valid zips: 0, skipped: 0", output)


if __name__ == "__main__":
    unittest.main()
