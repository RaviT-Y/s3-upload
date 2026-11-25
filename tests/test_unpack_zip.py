"""Tests for scripts/unpack_zip.py and the unpacked-size limit of scripts/check_zips.py."""

import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS)
import check_zips  # noqa: E402


def make_zip(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)


class UnpackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.zip = os.path.join(self.tmp.name, "a.zip")
        self.dest = os.path.join(self.tmp.name, "out", "api")

    def unpack(self, kind, files, dest=None):
        make_zip(self.zip, files)
        return subprocess.run([sys.executable, "-I", "-B", os.path.join(SCRIPTS, "unpack_zip.py"), kind, self.zip,
                               dest or self.dest, "1"], capture_output=True, text=True)

    def unpacked(self):
        return sorted(os.path.relpath(os.path.join(d, n), self.dest) for d, _, names in os.walk(self.dest) for n in names)

    def test_api_leaves_out_every_debug_output_folder(self):
        proc = self.unpack("api", {
            "metadata.json": "{}", "others.txt": "x", "h/armor_reports/json_reports/r.json": "{}",
            "h/debug_output/logs/diagnostics.log": "log", "h/debug_output/ast_diffs/a/b/c.json": "{}",
            "debug_output/x.txt": "x", "h/notdebug_output/y.txt": "y", "h/my_debug_output.txt": "z"})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.unpacked(), ["h/armor_reports/json_reports/r.json", "h/my_debug_output.txt",
                                           "h/notdebug_output/y.txt", "metadata.json", "others.txt"])
        self.assertIn("5 file(s) unpacked, 3 left out", proc.stdout)

    def test_abi_keeps_only_abi_metadata_json(self):
        proc = self.unpack("abi", {"abi_metadata.json": "{}", "lib.txt": "report", "sub/abi_metadata.json": "{}"})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.unpacked(), ["abi_metadata.json"])

    def test_missing_metadata_file_fails(self):
        for kind, files in (("api", {"others.txt": "x"}), ("abi", {"metadata.json": "{}"})):
            proc = self.unpack(kind, files, dest=os.path.join(self.tmp.name, "out", kind))
            self.assertEqual(proc.returncode, 1, kind)
            self.assertIn("is not in the zip", proc.stdout)

    def test_existing_folder_is_never_reused(self):
        os.makedirs(self.dest)
        self.assertNotEqual(self.unpack("api", {"metadata.json": "{}"}).returncode, 0)

    def test_names_cannot_leave_the_folder_even_if_one_got_through(self):
        proc = self.unpack("api", {"metadata.json": "{}", "../../escaped.txt": "x", "/tmp/escaped2.txt": "x"})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for folder, _, names in os.walk(self.tmp.name):
            for name in names:
                if name.startswith("escaped"):
                    self.assertTrue(os.path.abspath(folder).startswith(os.path.abspath(self.dest)), folder)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "escaped.txt")))

    def test_unpacked_files_get_no_special_permissions(self):
        with zipfile.ZipFile(self.zip, "w") as archive:
            info = zipfile.ZipInfo("metadata.json")
            info.create_system = 3
            info.external_attr = 0o104755 << 16
            archive.writestr(info, "{}")
        subprocess.run([sys.executable, "-I", "-B", os.path.join(SCRIPTS, "unpack_zip.py"), "api", self.zip, self.dest],
                       capture_output=True, text=True, check=True)
        self.assertFalse(os.stat(os.path.join(self.dest, "metadata.json")).st_mode & 0o111)


class UnpackedSizeLimitTest(unittest.TestCase):
    def test_zip_that_is_huge_once_unpacked_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bomb.zip")
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("a.txt", "a" * 600)
                archive.writestr("b.txt", "b" * 600)
            self.assertIsNone(check_zips.check(path, {"txt"}))
            limit = check_zips.MAX_UNPACKED_BYTES
            check_zips.MAX_UNPACKED_BYTES = 1000
            try:
                self.assertEqual(check_zips.check(path, {"txt"}), ("too-large-unpacked", "1200"))
            finally:
                check_zips.MAX_UNPACKED_BYTES = limit


if __name__ == "__main__":
    unittest.main()
