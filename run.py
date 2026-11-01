"""
Command-line runner.
  python run.py --target practice
  python run.py --target demo-vulnerable --attacks direct-override encoding --mutations 1 --budget 10
  python run.py --list
"""
import argparse

from attacks import ATTACKS
from redteam_agent import get_run, run_attacks, save_run
from report import to_markdown
from targets import build_target


def main():
    parser = argparse.ArgumentParser(description="AgentAttacker: automated red-teaming for LLM chatbots")
    parser.add_argument("--target", choices=["practice", "demo-vulnerable", "demo-hardened"], default="practice")
    parser.add_argument("--attacks", nargs="*", help="attack ids (default: all)")
    parser.add_argument("--mutations", type=int, default=0, help="adaptive rewrites per failed attack")
    parser.add_argument("--budget", type=int, default=15, help="max Gemini calls for the whole run")
    parser.add_argument("--list", action="store_true", help="list attacks and exit")
    args = parser.parse_args()

    if args.list:
        for a in ATTACKS:
            print(f"{a.id:18} {a.owasp}  {a.category:20} {a.name}")
        return

    target = build_target({"kind": args.target})
    attacker = None
    if args.mutations:
        from llm import gemini
        attacker = gemini(temperature=0.9)

    def progress(node, update):
        if node == "judge":
            r = update["results"][0]
            mark = "VULNERABLE" if r["success"] else "defended"
            print(f"  [{mark:10}] {r['attack_id']:18} attempt {r['attempt']}  {r['evidence']}", flush=True)

    print(f"Attacking '{target.label}'...")
    results, summary = run_attacks(target, args.attacks or [a.id for a in ATTACKS], attacker,
                                   args.mutations, args.budget, on_update=progress)
    run_id = save_run(target.info(), results, summary, {"mutations": args.mutations, "budget": args.budget})
    print(f"\nAttack success rate: {summary['attack_success_rate']:.0%} "
          f"({summary['attacks_succeeded']}/{summary['attacks_tested']}) · Gemini calls: {summary['llm_calls']}")
    print(f"Saved run {run_id}\n")
    print(to_markdown(get_run(run_id))[:300] + "...")


if __name__ == "__main__":
    main()
