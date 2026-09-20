import json
from pathlib import Path

cases_dir = Path("cases")

case_files = sorted(cases_dir.glob("CASE-*.json"), reverse=True)

if not case_files:
    print("No case files found.")
    raise SystemExit

print("\nAvailable cases:\n")

for number, case_file in enumerate(case_files, start=1):
    with open(case_file, "r") as file:
        case = json.load(file)

    print(
        f"{number}. {case.get('case_id')} | "
        f"{case.get('severity')} | "
        f"{case.get('description')}"
    )

choice = int(input("\nSelect case number: ")) - 1

selected_file = case_files[choice]

with open(selected_file, "r") as file:
    case = json.load(file)

print("\n=== CASE REVIEW ===\n")
print(json.dumps(case, indent=2))

print("\nAnalyst decision:")
print("1. Approve")
print("2. Escalate")
print("3. Close")
print("4. Keep Pending")

decision = input("\nChoose 1-4: ")

decision_map = {
    "1": "Approved",
    "2": "Escalated",
    "3": "Closed",
    "4": "Pending"
}

case["analyst_decision"] = decision_map.get(decision, "Pending")

note = input("Analyst note: ")
case["analyst_note"] = note

with open(selected_file, "w") as file:
    json.dump(case, file, indent=2)

print(f"\nCase updated: {selected_file}")
print(f"Decision: {case['analyst_decision']}")
