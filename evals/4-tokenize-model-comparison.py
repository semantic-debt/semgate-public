"""Rebuild all frozen prompts and count tokens without calling any model API."""
from __future__ import annotations
import importlib.util, json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
baseline=load(ROOT/'evals/1-run-jev-dataset-eval.py','baseline_loader')
adapter=load(ROOT/'evals/model-comparison-adapter.py','comparison_adapter')

def build_cases():
 cases=[]; baseline.load_rjudge(cases); baseline.load_injec(cases); unavailable,taken=baseline.load_abstention(cases,1000)
 assert len(cases)==2622
 assert sum(baseline.split_dev(c) for c in cases)==524
 return cases,unavailable,taken

def main():
 cases,unavailable,taken=build_cases(); prompts=[adapter.render(c) for c in cases]
 canonical=[json.dumps(p,ensure_ascii=False,separators=(',',':')) for p in prompts]
 result={'schema':'semgate-model-comparison-token-preflight/1','cases':len(cases),'dev_cases':sum(baseline.split_dev(c) for c in cases),'held_out_cases':sum(not baseline.split_dev(c) for c in cases),'prompt_characters':sum(map(len,canonical)),'paid_api_calls':0,'paid_cost_usd':0.0,'models':{},'abstention_unavailable_components':unavailable}
 import tiktoken
 try: enc=tiktoken.encoding_for_model('gpt-5')
 except KeyError: enc=tiktoken.get_encoding('o200k_base')
 result['models']['gpt-5']={'input_tokens':sum(len(enc.encode(x)) for x in canonical),'tokenizer':enc.name,'exact_for_rendered_canonical_messages':True,'note':'Counts canonical role/content JSON. Provider framing overhead, if any, must be added by its official request tokenizer.'}
 from transformers import AutoTokenizer
 tok=AutoTokenizer.from_pretrained('IFM/K2-Horizon-7B',trust_remote_code=True)
 k2=0
 for i,p in enumerate(prompts):
  try: ids=tok.apply_chat_template(p,tokenize=True,add_generation_prompt=True)
  except Exception: ids=tok.encode(canonical[i],add_special_tokens=True)
  k2+=len(ids)
 result['models']['IFM/K2-Horizon-7B-Uno']={'input_tokens':k2,'tokenizer':'IFM/K2-Horizon-7B official tokenizer + chat template','exact_for_rendered_messages':True,'api_cost_usd_if_self_hosted':0.0}
 result['models']['gemini-3.1-flash-lite']={'input_tokens':None,'exact_count_status':'blocked_without provider countTokens route','prompt_characters':result['prompt_characters'],'note':'Google does not publish an offline tokenizer guaranteed identical to the service. Exact input count requires the official countTokens API; no Gemini credential is connected. No estimate is mislabeled as exact.'}
 out=ROOT/'evals/model-comparison-token-preflight.json'; out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n'); print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__': main()
