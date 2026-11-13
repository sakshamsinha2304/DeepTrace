"""Combine detailed evidence into one conservative primary finding."""

from __future__ import annotations

from typing import Any


def build_primary_finding(
    antivirus_scan: dict[str, Any],
    threat_intel: dict[str, Any],
    eicar_test: dict[str, Any],
    static_triage: dict[str, Any],
    neural_detection: dict[str, Any],
) -> dict[str, str]:
    detections = antivirus_scan.get("detections") or []
    if antivirus_scan.get("status") == "DETECTED":
        names = list(dict.fromkeys(
            str(item.get("threat_name")) for item in detections if item.get("threat_name")
        ))
        non_test_names = [name for name in names if "eicar" not in name.casefold()]
        eicar_only_match = bool(eicar_test.get("status") == "MATCHED" and names and not non_test_names)
        if not eicar_only_match:
            return {
                "status": "DETECTED",
                "title": "Threat detected",
                "message": f"{antivirus_scan.get('engine', 'Antivirus scan')} identified {', '.join(non_test_names or names) or 'a threat (name unavailable)'}.",
                "source": str(antivirus_scan.get("engine", "Antivirus scan")),
            }

    static_flag = (static_triage.get("risk_index") or 0) >= 25
    model_flag = neural_detection.get("status") == "SCORED" and neural_detection.get("label") == "MODEL_FLAG"
    if eicar_test.get("status") == "MATCHED":
        if static_flag or model_flag:
            return {
                "status": "NEEDS_REVIEW",
                "title": "Test pattern found; review other clues",
                "message": "The harmless EICAR test pattern matched, and other checks raised review clues. The pattern does not classify the rest of the file.",
                "source": "Exact pattern plus secondary checks",
            }
        return {
            "status": "TEST_PATTERN",
            "title": "EICAR test pattern found",
            "message": "The known harmless test pattern matched. Other archive contents, if present, are not classified by this match.",
            "source": "Exact byte signature",
        }

    if threat_intel.get("status") == "FOUND":
        family = threat_intel.get("signature") or "a known sample"
        first_seen = threat_intel.get("first_seen")
        date_note = f" (first seen {first_seen} UTC)" if first_seen else ""
        av_note = " Defender reported no matching signature." if antivirus_scan.get("status") == "NO_DETECTION" else ""
        return {
            "status": "THREAT_INTEL_MATCH",
            "title": "Known hash match",
            "message": f"MalwareBazaar lists this SHA-256 as {family}{date_note}.{av_note} This is a database record, not a fresh scan.",
            "source": "MalwareBazaar hash record",
        }

    if antivirus_scan.get("status") == "NO_DETECTION":
        if static_flag or model_flag:
            clues = []
            if static_flag:
                clues.append("static indicators")
            if model_flag:
                clues.append("the research model")
            return {
                "status": "NEEDS_REVIEW",
                "title": "Needs review",
                "message": f"No Defender signature matched; {' and '.join(clues)} raised review clues. These clues do not confirm malware.",
                "source": "Defender scan plus secondary checks",
            }
        return {
            "status": "NO_DETECTION",
            "title": "No threat detected",
            "message": "Defender completed a scan with no matching signature. A clean scan cannot prove the file is safe.",
            "source": str(antivirus_scan.get("engine", "Antivirus scan")),
        }

    if static_flag or model_flag:
        clues = []
        if static_flag:
            clues.append("static indicators")
        if model_flag:
            clues.append("the research model")
        return {
            "status": "NEEDS_REVIEW",
            "title": "Needs review",
            "message": f"The antivirus scan was unavailable; {' and '.join(clues)} raised review clues but cannot confirm malware.",
            "source": "Static checks and research model",
        }

    return {
        "status": "UNVERIFIED",
        "title": "Unable to verify",
        "message": "The antivirus scan was unavailable. The remaining checks cannot determine whether the file is malicious.",
        "source": "No confirmed antivirus result",
    }
