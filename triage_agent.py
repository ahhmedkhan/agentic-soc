import requests
import json
from datetime import datetime
from pathlib import Path
import uuid
def generate_ai_summary(case):
    prompt = f"""
You are assisting a SOC analyst with security alert triage.

Use only the evidence contained in the case below.

Rules:
- Do not invent facts.
- Do not assume malicious intent.
- Do not call activity malicious, compromised, or benign unless the evidence explicitly supports that conclusion.
- A MITRE ATT&CK mapping describes possible technique context; it does not prove an attack occurred.
- Clearly distinguish observed facts from possible interpretations.
- Preserve the deterministic severity, confidence, and risk score exactly as provided.
- If evidence is insufficient, state that validation is required.
- Treat related_endpoint_events as supporting investigation context, not proof of compromise.
- Recommend concrete analyst checks based on the evidence.

Case:
{json.dumps(case, indent=2)}

Return:
1. Investigation summary
2. Observed evidence
3. Why it was scored this way
4. Recommended next checks
"""

    response = requests.post(
    "http://127.0.0.1:11434/api/generate",
    json={
        "model": "qwen2.5:1.5b",
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 180,
            "temperature": 0.2
        }
    },
    timeout=60
)

    response.raise_for_status()

    return response.json()["response"].strip()
def triage_alert(alert):
    score = 0
    reasons = []
    recommendations = []

    rule_id = str(alert.get("rule_id", ""))
    wazuh_level = int(alert.get("wazuh_level", 0))
    username = str(alert.get("user", "N/A"))
    source_ip = str(alert.get("source_ip", "N/A"))
    description = str(alert.get("description", ""))
    mitre_id = alert.get("mitre_id", [])
    mitre_technique = alert.get("mitre_technique", [])

    # Base severity from Wazuh
    if wazuh_level >= 10:
        score += 4
        reasons.append("High Wazuh alert level")
    elif wazuh_level >= 7:
        score += 3
        reasons.append("Elevated Wazuh alert level")
    elif wazuh_level >= 4:
        score += 2
        reasons.append("Moderate Wazuh alert level")
    else:
        score += 1

    # Failed login rule
    if rule_id == "60122":
        reasons.append("Authentication failure detected")
        recommendations.append(
            "Review related authentication events for repeated failures."
        )

    # Source-IP context
    if source_ip in ("127.0.0.1", "::1"):
        reasons.append("Source is localhost")
        score -= 1
    elif source_ip not in ("N/A", "-", ""):
        reasons.append(f"Authentication originated from remote source {source_ip}")
        score += 2
        recommendations.append(
            "Check whether the source IP is expected for this endpoint."
        )

    # Username context
    if username.lower() in ("administrator", "admin", "root"):
        score += 2
        reasons.append("Privileged account targeted")

    if username.lower() in ("fakeuser", "test", "testuser"):
        reasons.append("Username resembles a test or lab account")


    related_failures = int(alert.get("related_failures") or 0)

    if related_failures >= 6:
        score += 4
        reasons.append(
            f"{related_failures} related failed logins detected within the correlation window"
        )
        recommendations.append(
            "Escalate for investigation of possible brute-force or credential-guessing activity."
        )

    elif related_failures >= 3:
        score += 2
        reasons.append(
            f"{related_failures} related failed logins detected within the correlation window"
        )
        recommendations.append(
            "Review authentication activity for repeated or automated login attempts."
        )

    elif related_failures >= 2:
        score += 1
        reasons.append(
            f"{related_failures} related failed logins detected within the correlation window"
        )
    # Keep the score within a simple range

    related_endpoint_events = alert.get("related_endpoint_events", [])

    if len(related_endpoint_events) >= 3:
        score += 3
        reasons.append(
            f"{len(related_endpoint_events)} related endpoint events detected in the same investigation window"
        )
        recommendations.append(
            "Review the correlated service-creation, registry, and process activity as one incident."
        )

    elif len(related_endpoint_events) == 2:
        score += 2
        reasons.append(
            "Multiple related endpoint events detected in the same investigation window"
        )
        recommendations.append(
            "Correlate the related endpoint events and validate whether the activity was authorized."
        )

    elif len(related_endpoint_events) == 1:
        score += 1
        reasons.append(
            "One related endpoint event detected in the same investigation window"
        )

    score = max(0, min(score, 10))

    if score >= 7:
        severity = "High"
    elif score >= 3:
        severity = "Medium"
    else:
        severity = "Low"

    if score >= 6:
        confidence = "High"
    elif score >= 3:
        confidence = "Medium"
    else:
        confidence = "Low"

    if not recommendations:
        recommendations.append(
            "Review surrounding endpoint activity and validate whether the event is expected."
        )
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    case = {
        "case_id": case_id,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "analyst_decision": "Pending",
        "case_type": "SOC Triage",
        "agent": alert.get("agent", "N/A"),
        "timestamp": alert.get("timestamp", "N/A"),
        "rule_id": rule_id,
        "description": description,
        "wazuh_level": wazuh_level,
        "user": username,
        "source_ip": source_ip,
        "related_failures": related_failures,
        "related_endpoint_events": related_endpoint_events,
        "mitre_id": mitre_id,
        "mitre_technique": mitre_technique,
        "severity": severity,
        "confidence": confidence,
        "risk_score": score,
        "reasons": reasons,
        "recommended_actions": recommendations,
        "analyst_approval_required": True
    }
    try:
        case["ai_summary"] = generate_ai_summary(case)
    except Exception as error:
        case["ai_summary"] = f"AI summary unavailable: {error}"
    return case
def save_case(case):
    cases_dir = Path("cases")
    cases_dir.mkdir(exist_ok=True)

    file_path = cases_dir / f"{case['case_id']}.json"

    with open(file_path, "w") as file:
        json.dump(case, file, indent=2)

    return file_path

if __name__ == "__main__":
    test_alert = {
        "timestamp": "2026-09-20T03:58:14+0400",
        "agent": "DESKTOP-BIMNT3G",
        "rule_id": "60122",
        "description": "Logon Failure - Unknown user or bad password",
        "wazuh_level": 5,
        "mitre_id": ["T1531"],
        "mitre_technique": ["Account Access Removal"],
        "user": "fakeuser",
        "source_ip": "::1"
    }

    result = triage_alert(test_alert)
    saved_path = save_case(result)
    print("\n=== SOC TRIAGE CASE ===\n")
    print(json.dumps(result, indent=2))
    print(f"\nCase saved to: {saved_path}")
