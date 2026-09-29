import json,os,sys
from pathlib import Path
from semgate.eval.runner import load_cases,evaluate_cases
from semgate.policy import Policy
from semgate.providers.typesafe import TypeSafeProvider
RATE=0.042
CEILING=0.10
case_path=Path('evals/real90.json')
raw=case_path.read_bytes()
# Conservative upper bound: two bytes per token plus 5k policy/provider overhead per case.
case_count=len(json.loads(raw)['cases'])
est_tokens=len(raw)/2 + case_count*5000
est_cost=est_tokens/1_000_000*RATE
if est_cost>=CEILING: raise SystemExit(f'budget preflight failed: ${est_cost:.4f} >= ${CEILING:.2f}')
if case_count!=90: raise SystemExit('expected exactly 90 cases')
report=evaluate_cases(load_cases([str(case_path)]),Policy.load('policies/default_policy.json'),provider=TypeSafeProvider(model='jev-latest'))
report['run']={'case_count':case_count,'estimated_input_token_upper_bound':round(est_tokens),'published_rate_usd_per_million_input_tokens':RATE,'estimated_cost_upper_bound_usd':round(est_cost,6),'approved_hard_ceiling_usd':CEILING,'dataset_content_committed':False}
Path('evals/jev-report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
