import json

from cspm import cli


def test_list_checks(capsys):
    assert cli.main(["--list-checks"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 10


def test_demo_exit_code_and_fail_on(capsys):
    assert cli.main(["--demo"]) == cli.EXIT_FINDINGS
    assert cli.main(["--demo", "--fail-on", "none"]) == cli.EXIT_OK
    # IAM-004 only yields medium findings
    assert cli.main(["--demo", "--checks", "IAM-004", "--fail-on", "high"]) == cli.EXIT_OK
    assert cli.main(["--demo", "--checks", "IAM-004", "--fail-on", "medium"]) == cli.EXIT_FINDINGS


def test_reports_written_and_valid(tmp_path):
    cli.main(["--demo", "--format", "json,md,html", "--output-dir", str(tmp_path), "--fail-on", "none"])
    files = {p.suffix: p for p in tmp_path.iterdir()}
    assert set(files) == {".json", ".md", ".html"}
    data = json.loads(files[".json"].read_text())
    assert data["summary"]["findings"] == 19 and len(data["checks"]) == 10
    assert data["meta"]["demo"] is True
    assert "sg-0a1b2c3d" in files[".md"].read_text()
    assert files[".html"].read_text().startswith("<!doctype html>")


def test_html_escapes_resource_names(tmp_path):
    from cspm.model import CheckMeta, CheckResult, Finding
    from cspm.report import to_html
    meta = CheckMeta("X-1", "t", "s", "LOW", "d", "r")
    res = CheckResult(meta, [Finding("X-1", "LOW", "<script>alert(1)</script>", "global", "m")], 1, [])
    out = to_html([res], {"account": "1", "generated": "now", "version": "0", "regions": []})
    assert "<script>alert" not in out and "&lt;script&gt;" in out


def test_unknown_check_is_usage_error(capsys):
    assert cli.main(["--demo", "--checks", "NOPE-1"]) == cli.EXIT_USAGE


def test_missing_credentials_is_usage_error(monkeypatch, capsys):
    monkeypatch.setenv("PATH", "")
    assert cli.main([]) == cli.EXIT_USAGE


FAKE_AWS = str(__import__("pathlib").Path(__file__).resolve().parent / "fake_aws.py")


def test_real_subprocess_path_matches_demo(monkeypatch, tmp_path):
    """AwsRunner -> subprocess -> JSON parsing -> error-code parsing, against a fake `aws`."""
    monkeypatch.setenv("CSPM_AWS_BIN", FAKE_AWS)
    args = ["--regions", "eu-west-1,us-east-1", "--format", "json", "--output-dir", str(tmp_path),
            "--fail-on", "none"]
    cli.main(args)
    data = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert data["summary"]["findings"] == 19
    assert data["summary"]["not_assessed"] == 0


def test_wrapper_script_end_to_end(tmp_path):
    import os
    import subprocess
    root = __import__("pathlib").Path(__file__).resolve().parent.parent
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "aws").symlink_to(FAKE_AWS)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CSPM_AWS_BIN=str(bindir / "aws"))
    proc = subprocess.run([str(root / "aws-posture-check"), "--regions", "eu-west-1,us-east-1",
                           "--checks", "S3-001", "--fail-on", "none"],
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "Scanning as arn:aws:iam::123456789012:user/demo-auditor" in proc.stderr
    assert "acme-public-assets" in proc.stdout
