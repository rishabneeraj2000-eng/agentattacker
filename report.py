"""Turn a saved run into a readable Markdown security report."""
from attacks import GOAL_LABELS

RECOMMENDATIONS = {
    "leak_secret": "Never put secrets in the system prompt; fetch them server-side only when needed. "
                   "Add output DLP that also checks encoded forms (base64, reversed, spaced).",
    "leak_prompt": "Assume the system prompt will leak: keep nothing sensitive in it, and filter outputs "
                   "for distinctive prompt fragments.",
    "exfil_email": "Enforce tool permissions outside the model: allowlist recipients, require human "
                   "approval for outbound actions, and check that the action matches the user's intent.",
    "hijack": "Mark external content as untrusted (spotlighting), and scan retrieved/processed content "
              "for injected instructions before it reaches the model.",
}


def to_markdown(run: dict) -> str:
    summary, results, target = run["summary"], run["results"], run["target"]
    lines = [
        f"# AgentAttacker security report: {target['label']}",
        "",
        f"_Run {run['id']} · {run['time']}_",
        "",
        f"**Attack success rate: {summary['attack_success_rate']:.0%}** "
        f"({summary['attacks_succeeded']} of {summary['attacks_tested']} attacks succeeded) · "
        f"Gemini calls used: {summary['llm_calls']}",
        "",
        "## Results by OWASP LLM Top 10 category",
        "| OWASP | Succeeded | Total | Rate |",
        "|---|---|---|---|",
        *[f"| {k} | {v['succeeded']} | {v['total']} | {v['rate']:.0%} |" for k, v in summary["by_owasp"].items()],
        "",
        "## Attacks",
        "| Attack | Category | OWASP | Result | Attempts | Defences that fired |",
        "|---|---|---|---|---|---|",
    ]
    for a in summary["per_attack"].values():
        result = "❌ VULNERABLE" if a["success"] else "✅ defended"
        lines.append(f"| {a['name']} | {a['category']} | {a['owasp']} | {result} | {a['attempts']} | "
                     f"{', '.join(a['defences']) or '-'} |")
    if summary.get("skipped"):
        lines += ["", "Not applicable to this target: " +
                  ", ".join(f"{s['name']} ({s['reason']})" for s in summary["skipped"])]

    failed_goals = {a["goal"] for a in summary["per_attack"].values() if a["success"]}
    if failed_goals:
        lines += ["", "## Recommendations"]
        lines += [f"- **{GOAL_LABELS[goal]}**: {RECOMMENDATIONS[goal]}" for goal in sorted(failed_goals)]

    lines += ["", "## Evidence (successful attempts)"]
    for r in results:
        if r["success"]:
            lines += [f"### {r['name']} (attempt {r['attempt']})",
                      f"- **Evidence:** {r['evidence']}",
                      f"- **Attack:** {r['document'] or r['prompt']}",
                      f"- **Reply:** {r['response'][:400]}", ""]
    return "\n".join(lines)
