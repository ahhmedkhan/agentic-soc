import json
import getpass
import requests
import urllib3
import re

def count_related_failures(search_url, username, password, user, agent):
    correlation_search = f'''
    search index=main 60122 _index_earliest=-10m
    | rex field=_raw "\\"name\\":\\"(?<wazuh_agent>[^\\"]+)\\""
    | rex field=_raw "\\"targetUserName\\":\\"(?<target_user>[^\\"]+)\\""
    | search wazuh_agent="{agent}" target_user="{user}"
    | stats count
    '''
def get_related_endpoint_events(search_url, username, password, agent):
    correlation_search = f'''
    search index=main _index_earliest=-5m "{agent}"
    | rex field=_raw "\\"id\\":\\"(?<related_rule_id>\\d+)\\""
    | rex field=_raw "\\"description\\":\\"(?<related_description>[^\\"]+)\\""
    | search related_rule_id IN ("61138","92307","92004")
    | stats latest(_time) as event_time values(related_description) as description by related_rule_id
    | sort related_rule_id
    '''

    data = {
        "search": correlation_search,
        "output_mode": "json"
    }

    response = requests.post(
        search_url,
        auth=(username, password),
        data=data,
        verify=False,
        timeout=30
    )

    response.raise_for_status()

    related_events = []

    for line in response.text.splitlines():
        if not line.strip():
            continue

        item = json.loads(line)

        if "result" in item:
            result = item["result"]

            related_events.append({
                "rule_id": result.get("related_rule_id", "N/A"),
                "description": result.get("description", "N/A"),
                "event_time": result.get("event_time", "N/A")
            })

    return related_events

    data = {
        "search": correlation_search,
        "output_mode": "json"
    }

    response = requests.post(
        search_url,
        auth=(username, password),
        data=data,
        verify=False,
        timeout=30
    )

    response.raise_for_status()

    for line in response.text.splitlines():
        if not line.strip():
            continue

        item = json.loads(line)

        if "result" in item:
            return int(item["result"].get("count", 0))

    return 0

from triage_agent import triage_alert, save_case
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_URL = "https://127.0.0.1:8089"
SEARCH_URL = f"{SPLUNK_URL}/services/search/jobs/export"

username = input("Splunk username: ")
password = getpass.getpass("Splunk password: ")

search_query = """
search index=main _index_earliest=-5m
| sort - _indextime
"""

data = {
    "search": search_query,
    "output_mode": "json"
}

def extract_wazuh_json(raw_event):
    match = re.search(r'ossec:\s*(\{.*\})', raw_event)

    if not match:
        return None

    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None

print("\nSearching Splunk for fresh Wazuh alerts...\n")

response = requests.post(
    SEARCH_URL,
    auth=(username, password),
    data=data,
    verify=False,
    timeout=30
)

response.raise_for_status()

events_found = 0

for line in response.text.splitlines():
    if not line.strip():
        continue

    item = json.loads(line)

    if "result" not in item:
        continue

    events_found += 1
    result = item["result"]

    raw_event = result.get("_raw", "")
    wazuh = extract_wazuh_json(raw_event)

    print("=" * 70)
    print(f"SOC ALERT {events_found}")
    print("=" * 70)

    if wazuh:
        rule = wazuh.get("rule", {})
        agent = wazuh.get("agent", {})
        data_fields = wazuh.get("data", {})
        mitre = rule.get("mitre", {})

        print("Timestamp:", wazuh.get("timestamp", "N/A"))
        print("Agent:", agent.get("name", "N/A"))
        print("Rule ID:", rule.get("id", "N/A"))
        print("Description:", rule.get("description", "N/A"))
        print("Wazuh Level:", rule.get("level", "N/A"))
        print("MITRE ID:", mitre.get("id", "N/A"))
        print("MITRE Technique:", mitre.get("technique", "N/A"))
        eventdata = data_fields.get("win", {}).get("eventdata", {})
        alert = {
            "timestamp": wazuh.get("timestamp", "N/A"),
            "agent": agent.get("name", "N/A"),
            "rule_id": rule.get("id", "N/A"),
            "description": rule.get("description", "N/A"),
            "wazuh_level": rule.get("level", 0),
            "mitre_id": mitre.get("id", []),
            "mitre_technique": mitre.get("technique", []),
            "user": eventdata.get("targetUserName", "N/A"),
            "source_ip": eventdata.get("ipAddress", "N/A")
        }
        if alert["rule_id"] in ("61138", "92307", "92004"):
            related_endpoint_events = get_related_endpoint_events(
                SEARCH_URL,
                username,
                password,
                alert["agent"]
            )
        else:
            related_endpoint_events = []

        alert["related_endpoint_events"] = related_endpoint_events

        print("Related endpoint events:", len(related_endpoint_events))

        for related_event in related_endpoint_events:
            print(
                f"  Rule {related_event['rule_id']}: "
                f"{related_event['description']}"
            )
        if alert["rule_id"] == "60122":
            related_failures = count_related_failures(
                SEARCH_URL,
                username,
                password,
                alert["user"],
                alert["agent"]
            ) or 0
        else:
            related_failures = 0

        alert["related_failures"] = related_failures

        print("Related failed logins:", related_failures)
        triage_result = triage_alert(alert)
        saved_path = save_case(triage_result)
        print("\n=== AUTOMATED TRIAGE ===")
        print(json.dumps(triage_result, indent=2))
        print(f"\nCase saved to: {saved_path}")
        print("User:", eventdata.get("targetUserName", "N/A"))
        print("Source IP:", eventdata.get("ipAddress", "N/A"))

        print("\nRAW EVIDENCE:")
        print(raw_event)

    else:
        print("Could not parse Wazuh JSON.")
        print(raw_event)

if events_found == 0:
    print("No fresh Wazuh alerts found.")
else:
    print(f"\nTotal alerts parsed: {events_found}")
