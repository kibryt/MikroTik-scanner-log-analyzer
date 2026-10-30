from main import LogAnalyzer, CSV_FIELDS
import pytest
import csv

SAMPLE_LOGS = [
    "2026-10-30 16:37:18 system,info router rebooted by console:admin@tty1/shutdown",
    "2026-10-30 16:37:19 interface,info lo link up",
    "2026-10-30 16:37:43 system,info,account user admin logged in via local",
    "2026-10-30 16:38:32 system,info,account user admin logged out via local",
    "2026-10-30 16:38:35 system,error,critical login failure for user admin via local",
    "2026-10-30 16:38:38 system,info,account user admin logged in via local",
    "2026-10-30 16:39:03 script,info test log, severity: high",
    "",
    " ",
    "#",
    "some_nonsense#"
]

EXPECTED_OUTPUT = [
    ["2026-10-30 16:37:18", "system", "info", "router rebooted by console:admin@tty1/shutdown"],
    ["2026-10-30 16:37:19", "interface", "info", "lo link up"],
    ["2026-10-30 16:37:43", "system,account", "info", "user admin logged in via local"],
    ["2026-10-30 16:38:32", "system,account", "info", "user admin logged out via local"],
    ["2026-10-30 16:38:35", "system,critical", "error", "login failure for user admin via local"],
    ["2026-10-30 16:38:38", "system,account", "info", "user admin logged in via local"],
    ["2026-10-30 16:39:03", "script", "info", "test log, severity: high"],
    None,
    None,
    None,
    None
]

@pytest.mark.parametrize("input, output", list(zip(SAMPLE_LOGS, EXPECTED_OUTPUT)))
def test_log_analyzer_parse_line(input, output):
    assert LogAnalyzer._parse_line(input) == output

def test_log_analyzer_parse_logs(tmp_path):
    log_file = tmp_path / "logs.txt"
    log_file.write_text("\n".join(SAMPLE_LOGS), encoding="utf-8")
    csv_file = tmp_path / "logs.csv"

    rows = LogAnalyzer(log_file).parse_logs(csv_file)
    expected_row = [row for row in EXPECTED_OUTPUT if row is not None]

    assert rows == len(expected_row)

    with open(csv_file, "r", newline="", encoding="utf-8") as f:
        csv_file_content = list(csv.reader(f))
    assert csv_file_content[0] == CSV_FIELDS
    assert csv_file_content[1:] == expected_row

def test_parse_logs_refuses_to_overwrite(tmp_path):
    log_file = tmp_path / "logs.txt"
    log_file.write_text("\n".join(SAMPLE_LOGS), encoding="utf-8")
    csv_file = tmp_path / "logs.csv"
    csv_file.write_text("i exist already", encoding="utf-8")

    with pytest.raises(FileExistsError):
        LogAnalyzer(log_file).parse_logs(csv_file)