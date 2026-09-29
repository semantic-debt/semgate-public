#!/usr/bin/env python3
"""Report Semgate shadow configuration readiness without printing secret values."""
from __future__ import annotations
import importlib.util
import json,os,re
from pathlib import Path
PINNED=re.compile(r'^jev-\d+\.\d+\.\d+$')
def context_status(context, session):
    """Classify the trusted-context file without printing its contents.

    Returns (json_valid, session_usable). session_usable mirrors the hook's
    requirement: a session-keyed entry with a non-blank string trusted_intent
    and a non-empty trusted_constraints object.
    """
    try:
        data=json.loads(Path(context).read_text(encoding='utf-8'))
    except Exception:
        return False, False
    if not isinstance(data,dict):
        return False, False
    entry=data.get(session) if session else None
    if not isinstance(entry,dict):
        return True, False
    intent,constraints=entry.get('trusted_intent'),entry.get('trusted_constraints')
    return True, bool(isinstance(intent,str) and intent.strip() and isinstance(constraints,dict) and constraints)
def main():
    model=(os.getenv('SEMGATE_JEV_MODEL') or '').strip();context=os.getenv('SEMGATE_TRUSTED_CONTEXT_FILE');key=(os.getenv('TYPESAFE_API_KEY') or '').strip()
    session=os.getenv('GEMINI_SESSION_ID');jev=os.getenv('SEMGATE_SHADOW_JEV','0')=='1'
    readable=bool(context and Path(context).is_file() and os.access(context,os.R_OK))
    json_valid,session_usable=context_status(context,session) if readable else (False,False)
    result={'jev_enabled':jev,'typesafe_api_key_present':bool(key),'pinned_model_configured':bool(PINNED.fullmatch(model)),'trusted_context_file_configured':bool(context),'trusted_context_file_readable':readable,'typesafe_sdk_available':importlib.util.find_spec('typesafe_sdk') is not None,'effective_session_id_configured':bool(session),'trusted_context_json_valid':json_valid,'trusted_context_session_usable':session_usable,'warning':'Gemini CLI environment-variable redaction or strict GitHub mode can remove TYPESAFE_API_KEY from the hook child. If key_present is false here under the effective hook environment, Jev cannot authenticate. Exit 0 means the gated values are configured and readable, not that the SDK is reachable, the key is authenticated, or the trusted context is usable; check the readiness fields above. typesafe_sdk_available means the module is discoverable, not that it imports, matches the pinned version, or can reach the service. Do not use this exit code alone as the go/no-go gate for a Jev experiment; confirm a non-fast-path evaluation has status ok first.'}
    print(json.dumps(result,indent=2));return 0 if all((not result['jev_enabled'] or result['typesafe_api_key_present'],not result['jev_enabled'] or result['pinned_model_configured'],not result['jev_enabled'] or result['trusted_context_file_readable'])) else 2
if __name__=='__main__':raise SystemExit(main())
