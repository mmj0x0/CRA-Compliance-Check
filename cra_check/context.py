# cra_check/context.py
import json
import re
import shutil as _shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

URL_PATTERN = re.compile(r"^(https?://|git@)")
SBOM_CANDIDATE_PATHS = ["sbom.json", "bom.json", ".github/sbom.json"]


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


def clone_repo(url: str, dest: Path, runner=subprocess.run) -> None:
    result = runner(["git", "clone", "--depth", "1", url, str(dest)], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed for {url}: {result.stderr.strip()}")


def find_sbom_in_repo(repo_path: Path) -> Optional[Path]:
    for rel in SBOM_CANDIDATE_PATHS:
        candidate = repo_path / rel
        if candidate.is_file():
            return candidate
    return None


def generate_sbom_with_syft(repo_path: Path, runner=subprocess.run, which=_shutil.which) -> Optional[dict]:
    if which("syft") is None:
        return None
    result = runner(["syft", str(repo_path), "-o", "cyclonedx-json"], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def resolve_input(source: str, offline: bool = False, workdir: Optional[Path] = None) -> ScanContext:
    if is_repo_url(source):
        clone_dir = workdir or Path(tempfile.mkdtemp(prefix="cra-check-"))
        clone_repo(source, clone_dir)

        sbom_path = find_sbom_in_repo(clone_dir)
        if sbom_path is not None:
            data, fmt = parse_sbom_file(sbom_path)
            return ScanContext(sbom=data, sbom_format=fmt, repo_path=clone_dir, source=source, offline=offline)

        generated = generate_sbom_with_syft(clone_dir)
        if generated is not None:
            return ScanContext(sbom=generated, sbom_format="cyclonedx", repo_path=clone_dir, source=source, offline=offline)

        return ScanContext(sbom=None, sbom_format=None, repo_path=clone_dir, source=source, offline=offline)

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"'{source}' is not a valid file path or recognized repo URL.")
    try:
        data, fmt = parse_sbom_file(path)
    except json.JSONDecodeError as exc:
        raise ValueError(f"'{source}' is not valid JSON: {exc}") from exc
    return ScanContext(sbom=data, sbom_format=fmt, repo_path=None, source=source, offline=offline)
