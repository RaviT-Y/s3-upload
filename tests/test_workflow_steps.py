"""Tests for the prepare, upload and finish steps of s3-upload.yml.

The step scripts are taken from the workflow file and run with `bash -e` (what the runner does), with a fake
`gh` that answers from files and a fake `aws` that keeps its "bucket" in a folder and logs every call.
"""

import json
import os
import subprocess
import tempfile
import unittest
import zipfile

try:
    import yaml
except ImportError:                                  # the tests only need PyYAML to read the workflow file
    yaml = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "s3-upload.yml")

FAKE_GH = '''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
if args[:1] != ["api"]:
    sys.exit(2)
parts = args[1].strip("/").split("/")                 # repos/<owner>/<repo>/actions/runs/<id>
path = os.path.join(os.environ["FAKE"], "runs", "%s__%s__%s.json" % (parts[1], parts[2], parts[5]))
if not os.path.exists(path):
    print("gh: Not Found (HTTP 404)", file=sys.stderr)
    sys.exit(1)
sys.stdout.write(open(path).read())
'''

FAKE_AWS = '''#!/usr/bin/env python3
import fnmatch, os, shutil, sys
fake = os.environ["FAKE"]
args = sys.argv[1:]
with open(os.path.join(fake, "aws.log"), "a") as log:
    log.write(" ".join(args) + "\\n")
store = os.path.join(fake, "bucket")
def local(url):
    return os.path.join(store, url[len("s3://"):])
if args[:2] == ["s3", "ls"]:
    if os.environ.get("FAKE_LS_FAIL"):
        print("An error occurred (AccessDenied) when calling the ListObjectsV2 operation", file=sys.stderr)
        sys.exit(255)
    path = local(args[2])
    parent, base = os.path.dirname(path), os.path.basename(path)
    hits = [n for n in (os.listdir(parent) if os.path.isdir(parent) else []) if n.startswith(base)]
    if hits:
        print("2026-11-20 10:00:00        1 " + hits[0])
        sys.exit(0)
    sys.exit(1)
if args[:2] == ["s3", "cp"]:
    if os.environ.get("FAKE_CP_FAIL") and os.environ["FAKE_CP_FAIL"] in args[2]:
        print("upload failed: fake error", file=sys.stderr)
        sys.exit(1)
    src, dest = args[2], args[3]
    if "--recursive" in args:
        excludes = [args[i + 1] for i, a in enumerate(args) if a == "--exclude"]
        for folder, _, names in os.walk(src):
            for name in names:
                rel = os.path.relpath(os.path.join(folder, name), src)
                if any(fnmatch.fnmatch(rel, pattern) for pattern in excludes):
                    continue
                target = os.path.join(local(dest), rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copy(os.path.join(folder, name), target)
    else:
        os.makedirs(os.path.dirname(local(dest)), exist_ok=True)
        shutil.copy(src, local(dest))
    sys.exit(0)
sys.exit(2)
'''


def step(name_start):
    with open(WORKFLOW, encoding="utf-8") as handle:
        steps = yaml.safe_load(handle)["jobs"]["publish"]["steps"]
    return next(item for item in steps if item["name"].startswith(name_start))


def step_script(name_start):
    return step(name_start)["run"]


@unittest.skipIf(yaml is None, "PyYAML is needed to read the workflow file")
class StepsBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cwd = os.path.join(self.tmp.name, "repo")
        self.fake = os.path.join(self.tmp.name, "fake")
        self.bin = os.path.join(self.tmp.name, "bin")
        for folder in (self.cwd, os.path.join(self.fake, "runs"), self.bin, os.path.join(self.cwd, "work", "downloads")):
            os.makedirs(folder)
        os.symlink(os.path.join(ROOT, "scripts"), os.path.join(self.cwd, "scripts"))
        for name, text in (("gh", FAKE_GH), ("aws", FAKE_AWS)):
            path = os.path.join(self.bin, name)
            with open(path, "w") as handle:
                handle.write(text)
            os.chmod(path, 0o755)
        for name in ("downloads.tsv", "skipped.tsv"):
            open(os.path.join(self.cwd, "work", "downloads", name), "w").close()

    # ---- fixtures
    def add_run(self, repo, run_id, **changes):
        run = {"status": "completed", "conclusion": "failure", "event": "pull_request", "head_branch": "feature",
               "pull_requests": [{"number": 42}]}
        run.update(changes)
        with open(os.path.join(self.fake, "runs", "%s__%s.json" % (repo.replace("/", "__"), run_id)), "w") as handle:
            json.dump(run, handle)

    def add_artifact(self, repo, run_id, kind, files=None, created="2026-11-20T10:23:45Z", metadata=None):
        if files is None:
            name = "metadata.json" if kind == "api" else "abi_metadata.json"
            meta = {"project_url": "https://github.com/" + repo, "pr_number": 42, "github_event": "pull_request",
                    "ref_name": "42/merge", "branch": "development", "head_sha": "refs/pull/42/merge"}
            meta.update(metadata or {})
            files = {name: json.dumps(meta), "others.txt": "[OK] a.h\n"}
            if kind == "api":
                files.update({"hdr/armor_reports/json_reports/api_diff_report_a.json": "{}",
                              "hdr/debug_output/logs/diagnostics.log": "log\n",
                              "hdr/debug_output/ast_diffs/x.json": "{}"})
            else:
                files.update({"libfoo.so.txt": "abidiff report\n"})
        folder = os.path.join(self.cwd, "work", "downloads", "%s__%s" % (repo.replace("/", "__"), run_id))
        os.makedirs(folder, exist_ok=True)
        zip_path = os.path.join(folder, kind + ".zip")
        with zipfile.ZipFile(zip_path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        row = [repo, str(run_id), kind, "7", created, "a" * 40, os.path.relpath(zip_path, self.cwd)]
        with open(os.path.join(self.cwd, "work", "downloads", "downloads.tsv"), "a") as handle:
            handle.write("\t".join(row) + "\n")

    # ---- running a step
    def run_step(self, name_start, **env):
        script = os.path.join(self.tmp.name, "step.sh")
        with open(script, "w") as handle:
            handle.write(step_script(name_start))
        literal = {key: value for key, value in step(name_start).get("env", {}).items() if "${{" not in str(value)}
        environment = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE=self.fake,
                           GH_TOKEN="x", S3_BUCKET="bucket", **literal, **env)
        return subprocess.run(["bash", "-e", script], cwd=self.cwd, env=environment, capture_output=True, text=True)

    def run_prepare(self):
        """The validate step, then the prepare step (it needs the S3 paths the validate step works out)."""
        self.validate_proc = self.run_step("Validate zips")
        self.assertEqual(self.validate_proc.returncode, 0, self.validate_proc.stdout + self.validate_proc.stderr)
        return self.run_step("Prepare upload")

    def read(self, *parts):
        with open(os.path.join(self.cwd, *parts)) as handle:
            return handle.read()

    def lines(self, *parts):
        return [line for line in self.read(*parts).splitlines() if line]

    def verified_files(self, folder):
        base = os.path.join(self.cwd, "work", "verified", folder)
        return sorted(os.path.relpath(os.path.join(d, n), base) for d, _, names in os.walk(base) for n in names)

    def skipped(self):
        return [line.split("\t") for line in self.lines("work", "downloads", "skipped.tsv")]

    def aws_log(self):
        path = os.path.join(self.fake, "aws.log")
        if not os.path.exists(path):
            return []
        with open(path) as handle:
            return handle.read().splitlines()

    def bucket_files(self):
        base = os.path.join(self.fake, "bucket", "bucket")
        return sorted(os.path.relpath(os.path.join(d, n), base) for d, _, names in os.walk(base) for n in names)


PREFIX = "2026/11/20/10/github.com/qualcomm/fastrpc/42/merge/100"


class PrepareTest(StepsBase):
    STEP = "Prepare upload"

    def test_good_api_and_abi_artifacts(self):
        self.add_run("qualcomm/fastrpc", 100)
        self.add_artifact("qualcomm/fastrpc", 100, "api")
        self.add_artifact("qualcomm/fastrpc", 100, "abi")
        proc = self.run_prepare()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.lines("work", "verified", "to_upload.tsv"), [
            "api\tqualcomm__fastrpc__100/api\t" + PREFIX, "abi\tqualcomm__fastrpc__100/abi\t" + PREFIX])
        self.assertEqual(self.verified_files("qualcomm__fastrpc__100/api"),
                         ["hdr/armor_reports/json_reports/api_diff_report_a.json", "metadata.json", "others.txt"])
        self.assertEqual(self.verified_files("qualcomm__fastrpc__100/abi"), ["abi_metadata.json"])
        self.assertEqual(self.skipped(), [])
        self.assertIn("Ready to upload: 2", proc.stdout)

    def test_time_comes_from_the_artifact_and_ref_from_the_metadata(self):
        self.add_run("qualcomm/fastrpc", 100, pull_requests=[{"number": 7}])
        self.add_artifact("qualcomm/fastrpc", 100, "abi", created="2027-01-02T03:59:59Z",
                          metadata={"pr_number": 7, "ref_name": "7/merge"})
        self.run_prepare()
        self.assertEqual(self.lines("work", "verified", "to_upload.tsv"), [
            "abi\tqualcomm__fastrpc__100/abi\t2027/01/02/03/github.com/qualcomm/fastrpc/7/merge/100"])

    def test_run_that_is_not_finished_is_not_an_error(self):
        self.add_run("qualcomm/fastrpc", 100, status="in_progress")
        self.add_artifact("qualcomm/fastrpc", 100, "api")
        proc = self.run_prepare()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.lines("work", "verified", "to_upload.tsv"), self.skipped()), ([], []))
        self.assertIn("not finished yet", proc.stdout)
        self.assertIn("run not finished yet: 1", proc.stdout)

    def test_run_without_run_information_is_skipped(self):
        self.add_artifact("qualcomm/fastrpc", 99, "api")
        proc = self.run_prepare()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.skipped(), [["qualcomm/fastrpc", "99", "api", "run-lookup-failed"]])
        self.assertEqual(self.lines("work", "verified", "to_upload.tsv"), [])

    def test_s3_path_for_every_kind_of_run(self):
        # (event, GitHub's branch, GitHub's PR list, metadata) -> the folder name in S3, as the old flow had it
        cases = [
            ("push", "development", [], {"github_event": "push", "pr_number": None, "ref_name": "development"}, "development"),
            ("push", "release/1.0", [], {"github_event": "push", "pr_number": None, "ref_name": "release/1.0"}, "release/1.0"),
            ("workflow_dispatch", "v2", [], {"github_event": "workflow_dispatch", "pr_number": None, "ref_name": "v2"}, "v2"),
            ("pull_request", "feature", [{"number": 42}], {}, "42/merge"),
            ("pull_request", "domain-discovery", [], {"pr_number": 422, "ref_name": "422/merge"}, "422/merge"),   # fork PR
            ("pull_request_target", "feature", [], {"github_event": "pull_request_target", "pr_number": None, "ref_name": "main"}, "main"),
        ]
        for number, (event, branch, prs, metadata, expected) in enumerate(cases, start=1):
            self.add_run("qualcomm/fastrpc", number, event=event, head_branch=branch, pull_requests=prs)
            self.add_artifact("qualcomm/fastrpc", number, "api", metadata=metadata)
        proc = self.run_prepare()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.skipped(), [])
        self.assertEqual([line.split("\t")[2] for line in self.lines("work", "verified", "to_upload.tsv")], [
            "2026/11/20/10/github.com/qualcomm/fastrpc/%s/%d" % (case[4], number) for number, case in enumerate(cases, start=1)])

    def test_metadata_must_match_the_run(self):
        wrong = {                                    # name: (event, branch, GitHub's PR list, metadata change, field named in the log)
            "pr_number": ("pull_request", "feature", [{"number": 42}], {"pr_number": 43}, "pr_number"),
            "pr_number as text": ("pull_request", "feature", [{"number": 42}], {"pr_number": "42"}, "pr_number"),
            "project_url": ("pull_request", "feature", [{"number": 42}], {"project_url": "https://github.com/other/repo"}, "project_url"),
            "github_event": ("pull_request", "feature", [{"number": 42}], {"github_event": "push"}, "github_event"),
            "other pull request in ref_name": ("pull_request", "feature", [{"number": 42}], {"ref_name": "43/merge"}, "ref_name"),
            "branch as ref_name of a pull request": ("pull_request", "feature", [{"number": 42}], {"ref_name": "main"}, "ref_name"),
            "fork pull request, ref_name not a number": ("pull_request", "feature", [], {"ref_name": "main"}, "ref_name"),
            "push to another branch": ("push", "development", [], {"github_event": "push", "pr_number": None, "ref_name": "main"}, "ref_name"),
        }
        for number, (name, (event, branch, prs, change, field)) in enumerate(wrong.items(), start=1):
            self.add_run("qualcomm/fastrpc", number, event=event, head_branch=branch, pull_requests=prs)
            self.add_artifact("qualcomm/fastrpc", number, "api", metadata=change)
        proc = self.run_prepare()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([row[3] for row in self.skipped()], ["metadata-mismatch"] * len(wrong))
        self.assertEqual(self.lines("work", "verified", "to_upload.tsv"), [])
        self.assertEqual(self.verified_files("."), ["to_upload.tsv"])               # the unpacked files were removed
        for field in ("pr_number", "project_url", "github_event", "ref_name"):
            self.assertIn("does not match the run in: " + field, proc.stdout)

    def test_missing_ref_name_uses_the_testing_default(self):
        # TESTING behaviour: remove together with default_ref in the workflow when ref_name is required
        self.add_run("qualcomm/fastrpc", 1, event="push", head_branch="development", pull_requests=[])
        self.add_artifact("qualcomm/fastrpc", 1, "api", metadata={"github_event": "push", "pr_number": None, "ref_name": None})
        self.add_run("qualcomm/fastrpc", 2)
        self.add_artifact("qualcomm/fastrpc", 2, "abi", files={"abi_metadata.json": json.dumps(           # key not there at all
            {"project_url": "https://github.com/qualcomm/fastrpc", "pr_number": 42, "github_event": "pull_request"})})
        proc = self.run_prepare()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.skipped(), [])
        self.assertEqual([line.split("\t")[2] for line in self.lines("work", "verified", "to_upload.tsv")], [
            "2026/11/20/10/github.com/qualcomm/fastrpc/ref-name-missing/1",
            "2026/11/20/10/github.com/qualcomm/fastrpc/ref-name-missing/2"])
        self.assertIn("no ref_name in metadata.json: using the testing default 'ref-name-missing'", self.validate_proc.stdout)
        self.assertIn("no ref_name in abi_metadata.json: using the testing default 'ref-name-missing'", self.validate_proc.stdout)

    def test_validate_step_logs_the_s3_paths_at_its_end(self):
        self.add_run("qualcomm/fastrpc", 100)
        self.add_artifact("qualcomm/fastrpc", 100, "api")
        self.add_artifact("qualcomm/fastrpc", 100, "abi")
        self.add_artifact("qualcomm/fastrpc", 101, "api", files={"run.sh": "echo"})      # skipped: no S3 path for it
        self.run_prepare()
        end = self.validate_proc.stdout[self.validate_proc.stdout.index("=== S3 paths"):]
        self.assertIn("   api s3://bucket/" + PREFIX + "/files/", end)
        self.assertIn("   abi s3://bucket/" + PREFIX + "/files/", end)
        self.assertNotIn("101", end.split("=== downloads.tsv")[0])

    def test_every_s3_destination_is_logged_at_the_end(self):
        self.add_run("qualcomm/fastrpc", 100)
        self.add_artifact("qualcomm/fastrpc", 100, "api")
        self.add_artifact("qualcomm/fastrpc", 100, "abi")
        proc = self.run_prepare()
        end = proc.stdout[proc.stdout.index("=== S3 destinations"):]
        base = "   s3://bucket/" + PREFIX + "/files/"
        for expected in ("-- api (qualcomm__fastrpc__100/api)", "-- abi (qualcomm__fastrpc__100/abi)",
                         base + "metadata.json   (", base + "others.txt   (9 bytes)",
                         base + "hdr/armor_reports/json_reports/api_diff_report_a.json   (2 bytes)",
                         base + "abi_metadata.json   ("):
            self.assertIn(expected, end)
        self.assertNotIn("debug_output", end)
        self.assertNotIn("libfoo", end)                                            # abidiff reports are not uploaded

    def test_ref_name_that_is_not_a_plain_folder_name_is_refused(self):
        # The run really was on that branch, so the match passes: only the folder-name rule can stop these.
        names = ["feature/x+y", "a/../b", "a..b", "a b", "/abs", "trailing/", "a//b", ".hidden/x", "x/.", "ünï", "a;b", "$(x)"]
        for number, ref in enumerate(names, start=1):
            self.add_run("qualcomm/fastrpc", number, event="push", head_branch=ref, pull_requests=[])
            self.add_artifact("qualcomm/fastrpc", number, "api",
                              metadata={"github_event": "push", "pr_number": None, "ref_name": ref})
        proc = self.run_prepare()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([row[3] for row in self.skipped()], ["invalid-ref"] * len(names))
        self.assertEqual(self.lines("work", "verified", "to_upload.tsv"), [])

    def test_unusable_metadata_and_missing_metadata(self):
        self.add_run("qualcomm/fastrpc", 1)
        self.add_artifact("qualcomm/fastrpc", 1, "api", files={"metadata.json": "this is not json"})
        self.add_run("qualcomm/fastrpc", 2)
        self.add_artifact("qualcomm/fastrpc", 2, "api", files={"metadata.json": "[1, 2]"})
        self.add_run("qualcomm/fastrpc", 3)
        self.add_artifact("qualcomm/fastrpc", 3, "api", files={"others.txt": "no metadata here"})
        self.add_run("qualcomm/fastrpc", 4)
        self.add_artifact("qualcomm/fastrpc", 4, "abi", files={"metadata.json": "{}", "x.txt": "only the api name"})
        self.run_prepare()
        self.assertEqual([row[3] for row in self.skipped()],
                         ["invalid-metadata", "invalid-metadata", "no-metadata", "no-metadata"])
        self.assertEqual(self.lines("work", "verified", "to_upload.tsv"), [])

    def test_odd_creation_time_is_skipped(self):
        self.add_run("qualcomm/fastrpc", 1)
        self.add_artifact("qualcomm/fastrpc", 1, "api", created="yesterday")
        self.run_prepare()
        self.assertEqual([row[3] for row in self.skipped()], ["unexpected-data"])

    def test_one_bad_artifact_does_not_stop_the_others(self):
        self.add_artifact("qualcomm/fastrpc", 1, "api")                         # GitHub knows nothing about this run
        self.add_run("qualcomm/fastrpc", 100)
        self.add_artifact("qualcomm/fastrpc", 100, "abi")
        self.run_prepare()
        self.assertEqual([row[3] for row in self.skipped()], ["run-lookup-failed"])
        self.assertEqual(self.lines("work", "verified", "to_upload.tsv"), ["abi\tqualcomm__fastrpc__100/abi\t" + PREFIX])


class UploadTest(StepsBase):
    STEP = "Upload to S3"

    def prepare(self, *kinds):
        self.add_run("qualcomm/fastrpc", 100)
        for kind in kinds:
            self.add_artifact("qualcomm/fastrpc", 100, kind)
        proc = self.run_prepare()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_api_files_go_up_with_metadata_json_last(self):
        self.prepare("api")
        proc = self.run_step(self.STEP)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        base = "s3://bucket/" + PREFIX + "/files"
        self.assertEqual(self.aws_log(), [
            "s3 ls " + base + "/metadata.json",
            "s3 cp work/verified/qualcomm__fastrpc__100/api " + base +
            " --recursive --exclude metadata.json --content-type application/octet-stream --only-show-errors",
            "s3 cp work/verified/qualcomm__fastrpc__100/api/metadata.json " + base +
            "/metadata.json --content-type application/octet-stream --only-show-errors"])
        self.assertEqual(self.bucket_files(), sorted(PREFIX_FILES("api")))
        self.assertIn("Uploaded: 1, already uploaded: 0", proc.stdout)

    def test_abi_uploads_only_abi_metadata_json(self):
        self.prepare("abi")
        proc = self.run_step(self.STEP)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        base = "s3://bucket/" + PREFIX + "/files"
        self.assertEqual(self.aws_log(), [
            "s3 ls " + base + "/abi_metadata.json",
            "s3 cp work/verified/qualcomm__fastrpc__100/abi/abi_metadata.json " + base +
            "/abi_metadata.json --content-type application/json --only-show-errors"])
        self.assertEqual(self.bucket_files(), sorted(PREFIX_FILES("abi")))

    def test_api_and_abi_of_the_same_run_do_not_hide_each_other(self):
        self.prepare("api", "abi")
        proc = self.run_step(self.STEP)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.bucket_files(), sorted(PREFIX_FILES("api") + PREFIX_FILES("abi")))

    def test_second_run_uploads_nothing_again(self):
        self.prepare("api", "abi")
        self.run_step(self.STEP)
        first = len(self.aws_log())
        proc = self.run_step(self.STEP)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual([line.split()[1] for line in self.aws_log()[first:]], ["ls", "ls"])
        self.assertIn("Uploaded: 0, already uploaded: 2", proc.stdout)

    def test_an_interrupted_upload_is_repeated(self):
        self.prepare("api")
        proc = self.run_step(self.STEP, FAKE_CP_FAIL="/metadata.json")      # everything but metadata.json went up
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn(PREFIX + "/files/metadata.json", self.bucket_files())
        proc = self.run_step(self.STEP)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(PREFIX + "/files/metadata.json", self.bucket_files())

    def test_s3_that_cannot_be_asked_is_an_error_and_uploads_nothing(self):
        self.prepare("api")
        proc = self.run_step(self.STEP, FAKE_LS_FAIL="1")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::cannot check S3 for s3://bucket/" + PREFIX + "/files: An error occurred (AccessDenied)", proc.stdout)
        self.assertEqual([line.split()[1] for line in self.aws_log()], ["ls"])

    def test_failed_upload_fails_the_step_but_the_others_go_on(self):
        self.prepare("api", "abi")
        proc = self.run_step(self.STEP, FAKE_CP_FAIL="/api")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::upload failed for qualcomm__fastrpc__100/api", proc.stdout)
        self.assertEqual(self.bucket_files(), sorted(PREFIX_FILES("abi")))

    def test_unsafe_lines_in_to_upload_are_refused(self):
        os.makedirs(os.path.join(self.cwd, "work", "verified"))
        with open(os.path.join(self.cwd, "work", "verified", "to_upload.tsv"), "w") as handle:
            handle.write("api\t../../etc\t" + PREFIX + "\n")
            handle.write("api\tok/api\t../" + PREFIX + "\n")
            handle.write("api\tok/api\t$(touch /tmp/pwned)\n")
            handle.write("tool\tok/api\t" + PREFIX + "\n")
            handle.write("api\tok/api\t2026/ünï/x\n")                       # letters outside a-z: the locale must not matter
        proc = self.run_step(self.STEP, LANG="en_US.UTF-8", LC_ALL="en_US.UTF-8")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.aws_log(), [])
        self.assertEqual(proc.stdout.count("::error::"), 5)


def PREFIX_FILES(kind):
    base = PREFIX + "/files/"
    if kind == "abi":
        return [base + "abi_metadata.json"]
    return [base + "metadata.json", base + "others.txt", base + "hdr/armor_reports/json_reports/api_diff_report_a.json"]


class FinishTest(StepsBase):
    STEP = "Fail the run if any artifact was skipped"

    def test_nothing_skipped_succeeds(self):
        proc = self.run_step(self.STEP)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Nothing was skipped.", proc.stdout)

    def test_skipped_artifacts_fail_the_run_and_are_listed(self):
        with open(os.path.join(self.cwd, "work", "downloads", "skipped.tsv"), "w") as handle:
            handle.write("qualcomm/fastrpc\t5\tapi\tunexpected-file-type\n")
            handle.write("qualcomm/fastrpc\t6\tabi\t\x1b[31mevil\n")
        proc = self.run_step(self.STEP)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::2 artifact(s) were skipped", proc.stdout)
        self.assertIn("   qualcomm/fastrpc\t5\tapi\tunexpected-file-type", proc.stdout)
        self.assertNotIn("\x1b", proc.stdout)

    def test_missing_skipped_file_fails_the_run(self):
        os.remove(os.path.join(self.cwd, "work", "downloads", "skipped.tsv"))
        proc = self.run_step(self.STEP)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("an earlier step did not finish", proc.stdout)


if __name__ == "__main__":
    unittest.main()
