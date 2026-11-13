"""Run an on-demand Microsoft Defender scan on an isolated temporary copy.

This module never executes submitted bytes. A named detection is returned only
when Defender records a matching event for the unique temporary sample path.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any
import xml.etree.ElementTree as ET


ENGINE_NAME = "Microsoft Defender Antivirus"
EVENT_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
SCAN_TIMEOUT_SECONDS = 120
EVENT_QUERY_WINDOW_MS = 600_000


def _unavailable(note: str) -> dict[str, Any]:
    return {
        "status": "UNAVAILABLE",
        "engine": ENGINE_NAME,
        "detections": [],
        "note": note,
    }


def _find_mpcmdrun() -> str | None:
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    platform_dir = program_data / "Microsoft" / "Windows Defender" / "Platform"
    try:
        versions = sorted(
            (path for path in platform_dir.iterdir() if path.is_dir()),
            key=lambda path: path.name,
            reverse=True,
        )
        for version in versions:
            candidate = version / "MpCmdRun.exe"
            if candidate.is_file():
                return str(candidate)
    except OSError:
        pass

    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    candidate = program_files / "Windows Defender" / "MpCmdRun.exe"
    if candidate.is_file():
        return str(candidate)
    return shutil.which("MpCmdRun.exe")


def _find_wevtutil() -> str | None:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidate = system_root / "System32" / "wevtutil.exe"
    return str(candidate) if candidate.is_file() else shutil.which("wevtutil.exe")


def _decode_xml(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"<\x00"):
        return raw.decode("utf-16-le", errors="replace")
    if raw.startswith(b"\x00<"):
        return raw.decode("utf-16-be", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def _event_fields(event: ET.Element) -> dict[str, str]:
    fields: dict[str, str] = {}
    for element in event.iter():
        if element.tag.rsplit("}", 1)[-1] != "Data":
            continue
        name = element.attrib.get("Name", "").strip()
        if name and element.text:
            fields[re.sub(r"[^a-z0-9]", "", name.casefold())] = element.text.strip()

    system_time = next(
        (element.attrib.get("SystemTime") for element in event.iter()
         if element.tag.rsplit("}", 1)[-1] == "TimeCreated"),
        None,
    )
    if system_time:
        fields["detectedat"] = system_time
    return fields


def _query_scan_events(wevtutil: str, path_token: str) -> tuple[bool, list[dict[str, Any]], bool, bool]:
    query = (
        f"*[System[(EventID=1116 or EventID=1000 or EventID=1001 or EventID=1002 or EventID=1005) and "
        f"TimeCreated[timediff(@SystemTime) <= {EVENT_QUERY_WINDOW_MS}]]]"
    )
    try:
        result = subprocess.run(
            [wevtutil, "qe", EVENT_CHANNEL, f"/q:{query}", "/f:xml", "/c:100"],
            capture_output=True,
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, [], False, False
    if result.returncode != 0:
        return False, [], False, False

    xml_text = _decode_xml(result.stdout)
    xml_text = re.sub(r"^\s*<\?xml[^>]*\?>", "", xml_text, count=1)
    if not xml_text.strip() or "<Event" not in xml_text:
        return True, [], False, False
    try:
        root = ET.fromstring(f"<Events>{xml_text}</Events>")
    except ET.ParseError:
        # Some wevtutil versions wrap each event separately; parsing the raw
        # document still works when the output contains a single event.
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return False, [], False, False

    token = path_token.casefold()
    detections: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    scan_ids: set[str] = set()
    completion_ids: set[str] = set()
    failed_ids: set[str] = set()
    for event in root.iter():
        if event.tag.rsplit("}", 1)[-1] != "Event":
            continue
        fields = _event_fields(event)
        event_id = next((element.text for element in event.iter()
                         if element.tag.rsplit("}", 1)[-1] == "EventID"), None)
        scan_id = fields.get("scanid")
        if event_id == "1000" and scan_id and any(token in value.casefold() for value in fields.values()):
            scan_ids.add(scan_id)
        elif event_id == "1001" and scan_id:
            completion_ids.add(scan_id)
        elif event_id in {"1002", "1005"} and scan_id:
            failed_ids.add(scan_id)

        if event_id != "1116":
            continue
        event_path = fields.get("path", "")
        if token not in event_path.casefold():
            continue

        threat_name = fields.get("threatname") or fields.get("name")
        if not threat_name:
            continue
        key = (threat_name.casefold(), event_path.casefold())
        if key in seen:
            continue
        seen.add(key)
        if len(detections) < 20:
            detections.append({
                "threat_name": threat_name,
                "severity": fields.get("severityname") or fields.get("severity"),
                "category": fields.get("categoryname") or fields.get("category"),
                "detection_type": fields.get("detectiontype"),
                "detection_source": fields.get("detectionsource"),
                "signature_version": fields.get("securityintelligenceversion") or fields.get("signatureversion"),
                "engine_version": fields.get("engineversion"),
                "detected_at": fields.get("detectedat"),
            })
    scan_confirmed = bool(scan_ids & completion_ids)
    scan_failed = bool(scan_ids & failed_ids)
    return True, detections, scan_confirmed, scan_failed


def _poll_scan_events(
    wevtutil: str,
    path_token: str,
    attempts: int = 4,
    delay_seconds: float = 0.35,
    stop_when_confirmed: bool = False,
) -> tuple[bool, list[dict[str, Any]], bool, bool]:
    """Poll briefly for a path-matched detection event that may arrive late."""
    attempts = min(max(1, attempts), 4)
    for attempt in range(attempts):
        log_readable, detections, scan_confirmed, scan_failed = _query_scan_events(wevtutil, path_token)
        if detections or not log_readable:
            return log_readable, detections, scan_confirmed, scan_failed
        if stop_when_confirmed and scan_confirmed and not scan_failed:
            return log_readable, detections, scan_confirmed, scan_failed
        if attempt + 1 < attempts:
            time.sleep(max(0.0, min(delay_seconds, 1.0)))
    return log_readable, detections, scan_confirmed, scan_failed


def _check_exclusion(mpcmdrun: str, sample_path: Path) -> bool | None:
    """Return True if excluded, False if eligible, or None if unknown."""
    try:
        result = subprocess.run(
            [mpcmdrun, "-CheckExclusion", "-Path", str(sample_path)],
            capture_output=True,
            timeout=10,
            check=False,
            cwd=str(Path(mpcmdrun).parent),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace").casefold()
    if "is excluded" in output and "is not excluded" not in output:
        return True
    if "is not excluded" in output:
        return False
    return None


def _detection_result(detections: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "DETECTED",
        "engine": ENGINE_NAME,
        "detections": detections,
        "note": "Microsoft Defender reported a matching detection for the temporary scan copy.",
    }


def _stdout_confirms_no_threats(scan_result: Any, sample_path: Path) -> bool:
    """Use exact scan output as secondary confirmation when event correlation is incomplete."""
    if scan_result.returncode != 0:
        return False
    output = (scan_result.stdout or b"") + (scan_result.stderr or b"")
    text = re.sub(r"\s+", " ", output.decode("utf-8", errors="replace").casefold())
    path_pattern = re.escape(str(sample_path).casefold())
    clean_result = re.compile(rf"\bscanning\s+['\"]?{path_pattern}['\"]?\s+found\s+no\s+threats\b")
    return clean_result.search(text) is not None


def scan_with_defender(data: bytes, filename: str) -> dict[str, Any]:
    """Scan a temporary copy using Defender and read matching Event ID 1116s.

    A successful scan with a readable event log and no matching detection is
    reported as NO_DETECTION. Any incomplete scan or unreadable event log is
    UNAVAILABLE; it is never treated as a clean result.
    """
    if os.name != "nt":
        return _unavailable("Microsoft Defender file scanning is available only through the Windows local service.")

    mpcmdrun = _find_mpcmdrun()
    wevtutil = _find_wevtutil()
    if not mpcmdrun:
        return _unavailable("Microsoft Defender's scan command was not found on this computer.")
    if not wevtutil:
        return _unavailable("Windows event-log tools are unavailable, so a scan result cannot be confirmed.")

    suffix = Path(filename.replace("\\", "/")).suffix
    if not re.fullmatch(r"\.[A-Za-z0-9]{1,16}", suffix):
        suffix = ".bin"

    try:
        with tempfile.TemporaryDirectory(prefix="deeptrace-defender-") as temp_dir:
            path_token = Path(temp_dir).name
            sample_path = Path(temp_dir) / f"{path_token}_sample{suffix}"
            try:
                sample_path.write_bytes(data)
            except OSError:
                _, detections, _, _ = _poll_scan_events(wevtutil, path_token)
                if detections:
                    return _detection_result(detections)
                return _unavailable("A temporary copy could not be prepared for the Defender scan.")
            exclusion = _check_exclusion(mpcmdrun, sample_path)
            if exclusion is True or exclusion is None:
                _, detections, _, _ = _poll_scan_events(wevtutil, path_token)
                if detections:
                    return _detection_result(detections)
            if exclusion is True:
                return _unavailable("Defender reports that the temporary scan path is excluded, so the file was not verified.")
            if exclusion is None:
                return _unavailable("Defender's scan exclusion status could not be checked, so the file was not verified.")
            try:
                scan_result = subprocess.run(
                    [mpcmdrun, "-Scan", "-ScanType", "3", "-File", str(sample_path)],
                    capture_output=True,
                    timeout=SCAN_TIMEOUT_SECONDS,
                    check=False,
                    cwd=str(Path(mpcmdrun).parent),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except subprocess.TimeoutExpired:
                _, detections, _, _ = _poll_scan_events(wevtutil, path_token)
                if detections:
                    return _detection_result(detections)
                return _unavailable("The Defender scan did not finish within two minutes.")
            except OSError:
                logging.getLogger(__name__).exception("Could not start Microsoft Defender scan")
                _, detections, _, _ = _poll_scan_events(wevtutil, path_token)
                if detections:
                    return _detection_result(detections)
                return _unavailable("Microsoft Defender could not start a scan on the temporary file copy.")

            log_readable, detections, scan_confirmed, scan_failed = _poll_scan_events(
                wevtutil,
                path_token,
                stop_when_confirmed=scan_result.returncode == 0,
            )
            if detections:
                return _detection_result(detections)
            stdout_confirms_clean = _stdout_confirms_no_threats(scan_result, sample_path)
            if scan_result.returncode == 0 and log_readable and (scan_confirmed or stdout_confirms_clean) and not scan_failed:
                return {
                    "status": "NO_DETECTION",
                    "engine": ENGINE_NAME,
                    "detections": [],
                    "note": "The scan completed with no matching detection. This does not prove the file is safe.",
                }
            if not log_readable:
                return _unavailable("The scan ran, but Windows did not provide readable detection events, so the result cannot be confirmed.")
            if not scan_confirmed or scan_failed:
                return _unavailable("The scan did not produce a matching Defender completion record, so the file was not verified.")
            return _unavailable("Microsoft Defender did not complete the scan successfully.")
    except OSError:
        logging.getLogger(__name__).exception("Could not prepare temporary Defender scan copy")
        return _unavailable("A temporary copy could not be prepared for the Defender scan.")
