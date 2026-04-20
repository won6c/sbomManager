import json
import os
from pathlib import Path
from typing import Dict, Any

def get_progress_files(root_dir: str):
    """Find all progress.json files in the project."""
    return Path(root_dir).rglob("progress.json")

def format_progress(name: str, data: Dict[str, Any]) -> str:
    """Format the progress data for display."""
    status = data.get("project_status", "Unknown")
    phase = data.get("current_phase", "Unknown")
    completed = data.get("completed_tasks", [])

    # Assuming we might add a 'todo' list to progress.json in the future
    todo = data.get("todo", [])

    output = [
        f"--- {name} ---",
        f"Status: {status}",
        f"Phase:  {phase}",
        f"Completed Tasks: {len(completed)}",
    ]
    if completed:
        output.append("Completed:")
        for i, task in enumerate(completed, 1):
            output.append(f"  {i}. {task}")

    if todo:
        output.append("To-Do:")
        for i, task in enumerate(todo, 1):
            output.append(f"  {i}. {task}")

    return "\n".join(output)

def format_session_log(log_path: Path) -> str:
    """Format session log into sections."""
    if not log_path.exists():
        return f"No log found for {log_path.parent.name}"

    with open(log_path, "r") as f:
        lines = f.readlines()

    # Group by date/timestamp (assuming lines start with date)
    sections = []
    current_section = []
    section_count = 0

    for line in lines:
        if any(line.startswith(f"{year}-") for year in ["2024", "2025", "2026"]):
            # Strip the date and keep only the description
            content = line.split(" - ", 1)[-1] if " - " in line else line.strip()
            if current_section:
                sections.append(current_section)
            section_count += 1
            current_section = [f"Session {section_count}", content]
        else:
            if current_section:
                current_section.append(line.strip())
            else:
                section_count += 1
                current_section = [f"Session {section_count}", line.strip()]

    if current_section:
        sections.append(current_section)

    formatted_logs = []
    for section in sections:
        formatted_logs.append("\n".join(section))

    return "\n\n".join(formatted_logs)

def main():
    root_path = Path(__file__).parent.resolve()
    root_progress_file = Path(root_path) / "progress.json"

    print("="*60)
    print(f" SBOM Manager - Project Progress Report")
    print("="*60)

    # 1. Process Progress
    if root_progress_file.exists():
        with open(root_progress_file, "r") as f:
            root_data = json.load(f)
            print(format_progress("ROOT", root_data))
            print("\n" + "-"*30 + "\n")

    for progress_file in get_progress_files(root_path):
        if progress_file == root_progress_file:
            continue
        domain_name = progress_file.parent.name
        try:
            with open(progress_file, "r") as f:
                data = json.load(f)
                print(format_progress(domain_name.upper(), data))
                print("\n")
        except Exception as e:
            print(f"Error reading {domain_name} progress: {e}")

    print("\n" + "="*60)
    print(f" SESSION LOG SUMMARY")
    print("="*60 + "\n")

    # 2. Process Session Logs
    for log_file in Path(root_path).rglob("SESSION_LOG.md"):
        domain_name = log_file.parent.name if log_file.parent.name != root_path.name else "ROOT"
        print(f"--- {domain_name.upper()} LOG ---")
        print(format_session_log(log_file))
        print("\n" + "-"*30 + "\n")

if __name__ == "__main__":
    main()
