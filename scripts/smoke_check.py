from __future__ import annotations

import json
import py_compile
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "config.py",
    "run.py",
    "app/main.py",
    "app/templates/dashboard.html",
    "app/templates/tool.html",
    "app/templates/client.html",
    "app/static/style.css",
    "collectors/jira.py",
    "collectors/sentinelone.py",
    "collectors/wazuh.py",
    "collectors/securonix.py",
    "collectors/microsoft_sentinel.py",
    "comparison/comparator.py",
)

EXPECTED_TOOL_KEYS = {
    "sentinelone",
    "wazuh",
    "securonix",
    "microsoft_sentinel",
}

EXPECTED_STATUS_VALUES = {
    "Equal",
    "Covered",
    "Mismatch",
    "Review",
    "Missing Tickets",
    "Partial Failure",
    "Error",
    "Unknown",
}

STATUS_FIELDS = {
    "status",
    "coverage_status",
    "tool_display_status",
    "coverage_display_status",
}

TRIAGING_SCAN_PATHS = (
    "app",
    "ARCHITECTURE.md",
    "PROJECT_STRUCTURE.md",
    "PROJECT_RULES.md",
    "CODING_GUIDELINES.md",
    "TODO.md",
)
OLD_EXTRA_TICKET_LABEL = "Tria" + "ging"


def project_path(relative_path: str) -> Path:
    return ROOT / relative_path


def check_required_files(errors: list[str]) -> None:
    missing = [
        path
        for path in REQUIRED_FILES
        if not project_path(path).exists()
    ]

    if missing:
        errors.append(
            "Missing required files: "
            + ", ".join(missing)
        )


def check_python_compile(errors: list[str]) -> None:
    python_files = [
        path
        for path in ROOT.rglob("*.py")
        if "__pycache__" not in path.parts
    ]

    for path in python_files:
        try:
            py_compile.compile(
                str(path),
                doraise=True
            )
        except py_compile.PyCompileError as exc:
            errors.append(
                f"Python compile failed: "
                f"{path.relative_to(ROOT)}: {exc.exc_type_name}"
            )


def load_latest_json(errors: list[str]) -> dict | None:
    latest_path = project_path("latest.json")

    if not latest_path.exists():
        errors.append(
            "latest.json not found; run python run.py first."
        )
        return None

    try:
        with latest_path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        errors.append(
            f"latest.json is not valid JSON: line {exc.lineno}"
        )
        return None

    if not isinstance(data, dict):
        errors.append("latest.json root must be an object.")
        return None

    return data


def check_dashboard_shape(
    data: dict,
    errors: list[str],
    warnings: list[str]
) -> None:
    tools = data.get("tools")

    if not isinstance(tools, list):
        errors.append("latest.json must contain tools[].")
        return

    if not tools:
        warnings.append("latest.json tools[] is empty.")
        return

    tool_keys = {
        tool.get("tool_key")
        for tool in tools
        if isinstance(tool, dict)
    }

    unexpected_keys = sorted(
        key
        for key in tool_keys
        if key and key not in EXPECTED_TOOL_KEYS
    )

    if unexpected_keys:
        warnings.append(
            "Unexpected tool keys present: "
            + ", ".join(unexpected_keys)
        )

    missing_known = sorted(
        EXPECTED_TOOL_KEYS - tool_keys
    )

    if missing_known:
        warnings.append(
            "Known tool keys not present in latest.json: "
            + ", ".join(missing_known)
        )


def check_status_values(
    data: dict,
    errors: list[str]
) -> None:
    values = set()

    for tool in data.get("tools", []):
        if not isinstance(tool, dict):
            continue

        for field in STATUS_FIELDS:
            value = tool.get(field)
            if value not in (None, ""):
                values.add(str(value))

        for client in tool.get("clients", []):
            if not isinstance(client, dict):
                continue

            for field in STATUS_FIELDS:
                value = client.get(field)
                if value not in (None, ""):
                    values.add(str(value))

    unexpected = sorted(
        value
        for value in values
        if value not in EXPECTED_STATUS_VALUES
    )

    if unexpected:
        errors.append(
            "Unexpected dashboard status values: "
            + ", ".join(unexpected)
        )


def text_files_under(path: Path):
    if path.is_file():
        yield path
        return

    for child in path.rglob("*"):
        if child.is_file() and child.suffix.lower() in {
            ".py",
            ".html",
            ".css",
            ".md",
            ".js",
        }:
            yield child


def check_old_extra_ticket_label(errors: list[str]) -> None:
    matches = []

    for relative_path in TRIAGING_SCAN_PATHS:
        path = project_path(relative_path)
        if not path.exists():
            continue

        for text_file in text_files_under(path):
            try:
                content = text_file.read_text(
                    encoding="utf-8"
                )
            except UnicodeDecodeError:
                continue

            if (
                OLD_EXTRA_TICKET_LABEL in content
                or OLD_EXTRA_TICKET_LABEL.lower() in content
            ):
                matches.append(
                    str(text_file.relative_to(ROOT))
                )

    if matches:
        errors.append(
            "Old extra-ticket status text found in: "
            + ", ".join(sorted(set(matches)))
        )


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    check_required_files(errors)
    check_python_compile(errors)
    data = load_latest_json(errors)

    if data is not None:
        check_dashboard_shape(
            data,
            errors,
            warnings
        )
        check_status_values(
            data,
            errors
        )

    check_old_extra_ticket_label(errors)

    print("Smoke check")
    print(f"  files: {'ok' if not errors else 'checked'}")
    print(f"  latest.json: {'ok' if data is not None else 'missing/invalid'}")

    if warnings:
        print("  warnings:")
        for warning in warnings:
            print(f"    - {warning}")

    if errors:
        print("  result: FAILED")
        for error in errors:
            print(f"    - {error}")
        return 1

    print("  result: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
