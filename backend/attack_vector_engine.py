"""Summarize observed file provenance and compare available timestamps."""

import re
import datetime
from typing import Dict, List, Any, Optional


def analyze_corruption_root_cause(data: bytes, pe_info: Dict[str, Any]) -> Dict[str, Any]:
    """Report parser-confirmed structure problems without inferring intent."""
    del data  # Intent cannot be established from a byte-pattern heuristic.
    indicators = list(pe_info.get("corruption_indicators", []))
    is_corrupted = bool(pe_info.get("is_corrupted", False))
    return {
        "is_corrupted": is_corrupted,
        "verdict": "STRUCTURAL_ANOMALY" if is_corrupted else "NO_ANOMALY_OBSERVED",
        "analysis_note": "A malformed structure can result from damage or deliberate modification. File structure alone does not establish intent or a MITRE technique.",
        "indicators": indicators,
    }


def correlate_forensic_timeline(
    compile_ts: Optional[int], 
    debug_ts: Optional[int], 
    extracted_strings: List[Dict[str, Any]],
    current_time: Optional[datetime.datetime] = None,
    download_record: Optional[Dict[str, Any]] = None,
    file_created_at: Optional[str] = None,
    file_modified_at: Optional[str] = None,
    reproducible_build_marker: bool = False,
) -> Dict[str, Any]:
    """Compare embedded timestamps and list host-side times with clear sources."""
    if current_time is None:
        current_time = datetime.datetime.now(datetime.timezone.utc)
        
    timeline_events = []
    timestamp_discrepancy = False
    discrepancy_details = "Two comparable timestamps were not available. Host-side times are listed separately and do not establish download source or tampering."
    severity = "LOW"
    comparison_basis = None
    host_reference: Optional[tuple[datetime.datetime, str]] = None

    if reproducible_build_marker:
        comparison_basis = "DETERMINISTIC_BUILD"
        discrepancy_details = "A reproducible-build marker is present. The PE header timestamp may be content-derived, so it is not compared as a wall-clock build time."

    # Event 1: PE Compile Timestamp
    compile_dt = None
    if not reproducible_build_marker and compile_ts not in (None, 0, 0xFFFFFFFF):
        try:
            compile_dt = datetime.datetime.fromtimestamp(compile_ts, tz=datetime.timezone.utc)
            timeline_events.append({
                "event": "PE_FILE_HEADER_COMPILED",
                "timestamp_raw": compile_ts,
                "timestamp_iso": compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "source": "IMAGE_FILE_HEADER.TimeDateStamp",
                "status": "EXTRACTED"
            })
        except Exception:
            compile_dt = None

    # Event 2: Debug CodeView Timestamp
    debug_dt = None
    if debug_ts not in (None, 0, 0xFFFFFFFF):
        try:
            debug_dt = datetime.datetime.fromtimestamp(debug_ts, tz=datetime.timezone.utc)
            timeline_events.append({
                "event": "DEBUG_CODEVIEW_RECORDED",
                "timestamp_raw": debug_ts,
                "timestamp_iso": debug_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "source": "IMAGE_DEBUG_DIRECTORY.TimeDateStamp",
                "status": "EXTRACTED"
            })
        except Exception:
            debug_dt = None

    # Host-side times are independent artifacts, not values recovered from
    # the binary. Keep their sources explicit and do not use them as proof of
    # timestomping.
    for label, timestamp, source in (
        ("BROWSER_DOWNLOAD_STARTED", (download_record or {}).get("download_started_at"), (download_record or {}).get("browser")),
        ("BROWSER_DOWNLOAD_COMPLETED", (download_record or {}).get("download_completed_at"), (download_record or {}).get("browser")),
        ("LOCAL_FILE_CREATED", file_created_at, "Windows file metadata"),
        ("LOCAL_FILE_MODIFIED", file_modified_at, "Windows file metadata"),
    ):
        if not timestamp:
            continue
        try:
            parsed = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=datetime.timezone.utc)
            timeline_events.append({
                "event": label,
                "timestamp_raw": int(parsed.timestamp()),
                "timestamp_iso": timestamp,
                "source": source or "Host artifact",
                "status": "HOST_REPORTED",
            })
            if label == "BROWSER_DOWNLOAD_COMPLETED":
                host_reference = (parsed, "browser-recorded download completion")
            elif label == "LOCAL_FILE_CREATED" and host_reference is None:
                host_reference = (parsed, "Windows file creation time")
        except (TypeError, ValueError, OverflowError):
            continue

    # Compare compile vs debug
    if compile_dt and debug_dt:
        comparison_basis = "PE_AND_DEBUG"
        diff_sec = abs((compile_dt - debug_dt).total_seconds())
        if diff_sec > 86400: # greater than 24 hours
            timestamp_discrepancy = True
            severity = "REVIEW"
            discrepancy_details = (
                f"PE header and debug timestamps differ: {compile_dt.strftime('%Y-%m-%d')} "
                f"differs from Debug Directory Timestamp ({debug_dt.strftime('%Y-%m-%d')}) by {diff_sec/86400:.1f} days. "
                "This disagreement merits review but does not prove tampering; both timestamps can be changed."
            )

    # For stripped PEs with no debug timestamp, compare the PE header value to
    # the best available host acquisition time. This is a chronology clue only.
    elif compile_dt and host_reference:
        comparison_basis = "PE_AND_HOST"
        host_dt, host_label = host_reference
        if compile_dt > host_dt:
            timestamp_discrepancy = True
            severity = "REVIEW"
            discrepancy_details = (
                f"The PE header timestamp ({compile_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) is later than the {host_label} "
                f"({host_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}). This chronology mismatch merits review, but does not prove tampering: "
                "PE timestamps can be changed, and deterministic builds can use content-derived values."
            )
        else:
            discrepancy_details = (
                f"The PE header timestamp predates the {host_label}. This ordering is consistent with a file built before acquisition, "
                "but timestamps alone do not prove when the file was built."
            )

    # A discrepancy is a lead for review, not proof of timestomping. File times
    # can be changed and PE timestamps are not cryptographically trustworthy.
    if compile_dt:
        if compile_dt.year < 2000:
            timestamp_discrepancy = True
            severity = "REVIEW"
            discrepancy_details = (
                f"Unusually old PE compile timestamp ({compile_dt.strftime('%Y-%m-%d')}) detected. "
                "This may be intentional, but the timestamp alone cannot establish tampering."
            )
        elif compile_dt > current_time + datetime.timedelta(days=1):
            timestamp_discrepancy = True
            severity = "REVIEW"
            discrepancy_details = (
                f"Future PE compile timestamp ({compile_dt.strftime('%Y-%m-%d')}) detected. "
                "This may be invalid or deliberately altered; compare with independent records."
            )

    if not timestamp_discrepancy and compile_dt and debug_dt:
        discrepancy_details = "PE and debug timestamps are within one day of each other. Both values can be modified."

    comparison_available = bool(compile_dt and (debug_dt or host_reference))

    # Sort events chronologically
    timeline_events.sort(key=lambda x: x["timestamp_raw"])

    return {
        "timestamp_discrepancy": timestamp_discrepancy,
        "comparison_available": comparison_available,
        "timestamp_comparison_basis": comparison_basis,
        "discrepancy_severity": severity if timestamp_discrepancy else "LOW" if comparison_available else "UNKNOWN",
        "discrepancy_analysis": discrepancy_details,
        "events": timeline_events
    }


def reconstruct_attack_vector(
    filename: str,
    data: bytes,
    pe_info: Dict[str, Any],
    corruption_info: Dict[str, Any],
    extracted_strings: List[Dict[str, Any]],
    origin_metadata: Optional[Dict[str, Any]] = None,
    download_record: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Extract indicators without claiming host provenance or live network activity."""
    discovered_ips = [s["value"] for s in extracted_strings if s["category"] == "NETWORK_IP"]
    discovered_urls = [s["value"] for s in extracted_strings if s["category"] == "NETWORK_URL"]
    discovered_pdbs = [s["value"] for s in extracted_strings if s["category"] == "DEBUG_PDB"]
    origin_metadata = origin_metadata or {}
    zone_id = origin_metadata.get("zone_id")
    zone_descriptions = {0: "Local computer", 1: "Local intranet", 2: "Trusted sites", 3: "Internet zone", 4: "Restricted sites"}
    recorded_host_url = origin_metadata.get("host_url")
    download_record = download_record if download_record and download_record.get("matched") else None
    source_origin = {
        "zone_id": zone_id,
        "zone_desc": zone_descriptions.get(zone_id),
        "host_url": recorded_host_url or (download_record or {}).get("final_url") or (discovered_urls[0] if discovered_urls else None),
        "host_url_source": "Zone.Identifier HostUrl" if recorded_host_url else "Browser download URL" if download_record else ("Extracted file string" if discovered_urls else None),
        "referrer_url": origin_metadata.get("referrer_url") or (download_record or {}).get("referrer_url"),
        "staging_ip": discovered_ips[0] if discovered_ips else None,
        "staging_port": None,
        "user_agent": None,
        "browser": (download_record or {}).get("browser"),
        "download_started_at": (download_record or {}).get("download_started_at"),
        "download_completed_at": (download_record or {}).get("download_completed_at"),
        "download_original_url": (download_record or {}).get("original_url"),
        "download_page_url": (download_record or {}).get("page_url"),
        "download_match_basis": (download_record or {}).get("match_basis"),
    }
    indicators = []
    if zone_id is not None:
        indicators.append(f"Zone.Identifier reports ZoneId={zone_id} ({zone_descriptions.get(zone_id, 'Unrecognized zone')}).")
    if recorded_host_url:
        indicators.append("HostUrl was supplied in Zone.Identifier metadata; it records an origin URL, not proof the URL is reachable or safe.")
    if source_origin["referrer_url"]:
        indicators.append("ReferrerUrl was supplied in Zone.Identifier metadata.")
    if download_record:
        indicators.append(f"{download_record['browser']} download history contains a completed record matching the selected file ({download_record.get('match_basis', 'path match')}).")
    if discovered_urls or discovered_ips:
        indicators.append("Network-like strings were observed in the file; no connection or origin is confirmed.")
    if corruption_info.get("is_corrupted"):
        indicators.append("Structural anomalies were observed in the file container.")
    if download_record:
        browser_name = download_record["browser"]
        likely_vector = f"Browser download recorded ({browser_name})"
        confidence = "Low" if "size" not in download_record.get("match_basis", "") and "SHA-256" not in download_record.get("match_basis", "") else "Medium"
        delivery_description = "A local browser download record matches this file path. The browser record provides its saved URL and download time; it documents the file transfer, but does not establish how a malicious file reached that page or prove the file is malicious."
    elif zone_id == 3 and recorded_host_url:
        likely_vector, confidence = "Internet-origin download (likely)", "Medium"
        delivery_description = "Zone.Identifier records an Internet zone and a HostUrl. This supports an Internet-origin download, but does not identify the application or prove how the file was delivered."
    elif zone_id == 3:
        likely_vector, confidence = "Internet-origin file", "Low"
        delivery_description = "Zone.Identifier marks the file as Internet-origin. No source URL or delivery mechanism is available."
    else:
        likely_vector, confidence = "Unable to determine", "Insufficient evidence"
        delivery_description = "Host-origin metadata does not establish a delivery mechanism. Browser, email, removable media, or endpoint records may be needed."
    return {"likely_entry_vector": likely_vector, "vector_confidence": confidence, "supporting_evidence": indicators, "delivery_method": "BROWSER_DOWNLOAD" if download_record else "INTERNET_DOWNLOAD" if zone_id == 3 and recorded_host_url else "UNKNOWN", "delivery_description": delivery_description, "mitre_initial_access": "Not established by available acquisition evidence", "source_origin": source_origin, "kill_chain_steps": [], "extracted_pdbs": discovered_pdbs, "extracted_ips": discovered_ips, "extracted_urls": discovered_urls}
