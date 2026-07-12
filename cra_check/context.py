import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

URL_PATTERN = re.compile(r"^(https?://|git@)")


@dataclass
class ScanContext:
    sbom: Optional[dict]
    sbom_format: Optional[str]
    repo_path: Optional[Path]
    source: str
    offline: bool = False


def detect_sbom_format(data: dict) -> Optional[str]:
    if "bomFormat" in data:
        return "cyclonedx"
    if "spdxVersion" in data:
        return "spdx"
    return None


def parse_sbom_file(path: Path) -> tuple:
    data = json.loads(Path(path).read_text())
    return data, detect_sbom_format(data)


def is_repo_url(source: str) -> bool:
    return bool(URL_PATTERN.match(source))


def resolve_input(source: str, offline: bool = False, workdir: Optional[Path] = None) -> ScanContext:
    if is_repo_url(source):
        raise NotImplementedError("Repo URL handling is added in a later task")

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"'{source}' is not a valid file path or recognized repo URL.")
    try:
        data, fmt = parse_sbom_file(path)
    except json.JSONDecodeError as exc:
        raise ValueError(f"'{source}' is not valid JSON: {exc}") from exc
    return ScanContext(sbom=data, sbom_format=fmt, repo_path=None, source=source, offline=offline)
