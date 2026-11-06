import json
import subprocess
import sys
from pathlib import Path

import pytest

from permit_policy.validation import UINT256_MAX

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
AT_TIME = 1_800_000_000


def run_cli(*arguments: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "permit_policy", *arguments],
        input=stdin,
        capture_output=True,
        check=False,
    )


def check_request(
    request: Path,
    *,
    policy: Path = EXAMPLES / "policy.json",
    at_time: int = AT_TIME,
    output_format: str = "json",
) -> subprocess.CompletedProcess[bytes]:
    return run_cli(
        "check",
        "--request",
        str(request),
        "--policy",
        str(policy),
        "--at-time",
        str(at_time),
        "--format",
        output_format,
    )


def write_request(tmp_path: Path, content: bytes) -> Path:
    path = tmp_path / "request.json"
    path.write_bytes(content)
    return path


def test_example_request_matches_policy() -> None:
    result = check_request(EXAMPLES / "request.json")
    report = json.loads(result.stdout)
    assert result.returncode == 0
    assert result.stderr == b""
    assert report["decision"] == "allow"
    assert report["findings"] == []
    assert report["permit"]["value"] == "1000000"


def test_example_rejects_a_different_spender() -> None:
    result = check_request(EXAMPLES / "rejected-spender.json")
    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert result.stderr == b""
    assert report["decision"] == "reject"
    assert [finding["code"] for finding in report["findings"]] == ["spender_mismatch"]


def test_request_can_be_read_from_stdin() -> None:
    result = run_cli(
        "check",
        "--request",
        "-",
        "--policy",
        str(EXAMPLES / "policy.json"),
        "--at-time",
        str(AT_TIME),
        stdin=(EXAMPLES / "request.json").read_bytes(),
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["decision"] == "allow"


@pytest.mark.parametrize("request_name", ["request.json", "rejected-spender.json"])
def test_text_output_agrees_with_json_decision(request_name: str) -> None:
    json_result = check_request(EXAMPLES / request_name)
    text_result = check_request(EXAMPLES / request_name, output_format="text")
    report = json.loads(json_result.stdout)
    assert text_result.returncode == json_result.returncode
    assert text_result.stderr == b""
    expected_prefix = b"Allowed:" if report["decision"] == "allow" else b"Rejected:"
    assert text_result.stdout.startswith(expected_prefix)
    for finding in report["findings"]:
        assert finding["field"].encode() in text_result.stdout


def test_full_uint256_survives_json_input_and_output(tmp_path: Path) -> None:
    request = json.loads((EXAMPLES / "request.json").read_text())
    request["message"]["value"] = UINT256_MAX
    policy = json.loads((EXAMPLES / "policy.json").read_text())
    policy["max_value"] = UINT256_MAX
    request_path = write_request(tmp_path, json.dumps(request).encode())
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    result = check_request(request_path, policy=policy_path)
    assert result.returncode == 0
    assert json.loads(result.stdout)["permit"]["value"] == str(UINT256_MAX)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"message":{"private-marker":',
        b'{"private-marker":1,"private-marker":2}',
        b'{"nested":{"private-marker":1,"private-marker":2}}',
        b'{"private-marker":NaN}',
        b'{"private-marker":Infinity}',
        b'{"private-marker":-Infinity}',
        b'{"private-marker":1e9999}',
        b'{"private-marker":1.0}',
        b'{"private-marker":' + b"9" * 5000 + b"}",
        b'{"private-marker":"\xff"}',
        b"[" * 2000 + b'"private-marker"' + b"]" * 2000,
    ],
)
def test_invalid_json_does_not_disclose_request_or_traceback(
    tmp_path: Path, payload: bytes
) -> None:
    result = check_request(write_request(tmp_path, payload))
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"Error:" in result.stderr
    assert b"private-marker" not in result.stderr
    assert b"Traceback" not in result.stderr


def test_unsupported_schema_is_invalid_input(tmp_path: Path) -> None:
    request = json.loads((EXAMPLES / "request.json").read_text())
    request["primaryType"] = "private-marker"
    result = check_request(write_request(tmp_path, json.dumps(request).encode()))
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"private-marker" not in result.stderr
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("source", ["request", "policy", "stdin"])
def test_inputs_larger_than_one_mib_are_rejected(tmp_path: Path, source: str) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (1024 * 1024 + 1))
    if source == "stdin":
        result = run_cli(
            "check",
            "--request",
            "-",
            "--policy",
            str(EXAMPLES / "policy.json"),
            "--at-time",
            str(AT_TIME),
            stdin=oversized.read_bytes(),
        )
    else:
        result = check_request(
            oversized if source == "request" else EXAMPLES / "request.json",
            policy=oversized if source == "policy" else EXAMPLES / "policy.json",
        )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"1 MiB" in result.stderr
    assert b"Traceback" not in result.stderr


def test_one_mib_is_an_inclusive_limit(tmp_path: Path) -> None:
    content = (EXAMPLES / "request.json").read_bytes()
    path = write_request(tmp_path, content + b" " * (1024 * 1024 - len(content)))
    assert check_request(path).returncode == 0


def test_size_limit_counts_utf8_bytes(tmp_path: Path) -> None:
    request = json.loads((EXAMPLES / "request.json").read_text())
    request["domain"]["name"] = "é" * (1024 * 1024 // 2)
    document = json.dumps(request, ensure_ascii=False)
    assert len(document) < 1024 * 1024
    result = check_request(write_request(tmp_path, document.encode("utf-8")))
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"1 MiB" in result.stderr


def test_invalid_policy_does_not_disclose_contents(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text('{"private-marker":NaN}')
    result = check_request(EXAMPLES / "request.json", policy=policy)
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"private-marker" not in result.stderr
    assert b"Traceback" not in result.stderr


def test_unknown_request_keys_are_not_disclosed(tmp_path: Path) -> None:
    request = json.loads((EXAMPLES / "request.json").read_text())
    request["message"]["private-marker\x1b[31m"] = 1
    result = check_request(write_request(tmp_path, json.dumps(request).encode()))
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"private-marker" not in result.stderr
    assert b"\x1b" not in result.stderr
    assert b"Traceback" not in result.stderr


def test_unknown_policy_keys_are_not_disclosed(tmp_path: Path) -> None:
    policy_data = json.loads((EXAMPLES / "policy.json").read_text())
    policy_data["private-marker\x1b[31m"] = 1
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(policy_data))
    result = check_request(EXAMPLES / "request.json", policy=policy)
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"private-marker" not in result.stderr
    assert b"\x1b" not in result.stderr
    assert b"Traceback" not in result.stderr


def test_text_findings_do_not_render_untrusted_domain_strings(tmp_path: Path) -> None:
    request = json.loads((EXAMPLES / "request.json").read_text())
    request["domain"]["name"] = "private-marker\x1b[31m"
    result = check_request(
        write_request(tmp_path, json.dumps(request).encode()), output_format="text"
    )
    assert result.returncode == 1
    assert b"private-marker" not in result.stdout
    assert b"\x1b" not in result.stdout
    assert result.stderr == b""


def test_policy_must_be_a_separate_file() -> None:
    result = run_cli(
        "check",
        "--request",
        str(EXAMPLES / "request.json"),
        "--policy",
        "-",
        "--at-time",
        str(AT_TIME),
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("source", ["request", "policy"])
def test_missing_file_has_a_clean_error(tmp_path: Path, source: str) -> None:
    missing = tmp_path / "missing.json"
    result = check_request(
        missing if source == "request" else EXAMPLES / "request.json",
        policy=missing if source == "policy" else EXAMPLES / "policy.json",
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"Error:" in result.stderr
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("timestamp", ["-1", "1.0", "true", "0x123", "9" * 5000])
def test_invalid_evaluation_time_has_a_clean_error(timestamp: str) -> None:
    result = run_cli(
        "check",
        "--request",
        str(EXAMPLES / "request.json"),
        "--policy",
        str(EXAMPLES / "policy.json"),
        "--at-time",
        timestamp,
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"Traceback" not in result.stderr


def test_evaluation_time_is_required() -> None:
    result = run_cli(
        "check",
        "--request",
        str(EXAMPLES / "request.json"),
        "--policy",
        str(EXAMPLES / "policy.json"),
    )
    assert result.returncode == 2
    assert result.stdout == b""
