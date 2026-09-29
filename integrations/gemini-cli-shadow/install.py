#!/usr/bin/env python3
"""Installer for the v0.60.0 shadow observer (POSIX and native Windows)."""
from __future__ import annotations
import json,os,shlex,shutil,subprocess,sys,tempfile,uuid
from pathlib import Path

def strip_json_comments(text):
    """Strip // and /* */ comments while preserving strings and line boundaries."""
    out=[];i=0;in_string=False;escaped=False
    while i<len(text):
        ch=text[i]
        if in_string:
            out.append(ch)
            if escaped: escaped=False
            elif ch=='\\': escaped=True
            elif ch=='"': in_string=False
            i+=1;continue
        if ch=='"': in_string=True;out.append(ch);i+=1;continue
        if text.startswith('//',i):
            end=text.find('\n',i+2)
            if end<0: break
            out.append('\n');i=end+1;continue
        if text.startswith('/*',i):
            end=text.find('*/',i+2)
            if end<0: raise ValueError('unterminated block comment')
            segment=text[i:end+2];out.append('\n'*segment.count('\n') if '\n' in segment else ' ');i=end+2;continue
        out.append(ch);i+=1
    if in_string: raise ValueError('unterminated string')
    return ''.join(out)
def upsert(groups,entry):
    clean=[]
    for group in groups:
        if not isinstance(group,dict):clean.append(group);continue
        group=dict(group);group['hooks']=[h for h in group.get('hooks',[]) if not(isinstance(h,dict) and h.get('name')=='semgate-shadow')]
        if group['hooks']:clean.append(group)
    groups[:]=clean;groups.append(entry)
def private_copy(src,dst):
    fd,tmp=tempfile.mkstemp(prefix=dst.name+'.',dir=dst.parent)
    try:
        if hasattr(os,'fchmod'):os.fchmod(fd,0o600)
        with open(src,'rb') as source,os.fdopen(fd,'wb') as target:shutil.copyfileobj(source,target);target.flush();os.fsync(target.fileno())
        os.replace(tmp,dst)
    except Exception:
        try:os.unlink(tmp)
        except OSError:pass
        raise
def hook_command(python,hook,log_path):
    """The installed hook command. POSIX: an env assignment prefix, quoted for
    sh. Windows shells have no `VAR=value cmd` form, so the log path is passed
    as `--log`, quoted with the Windows argument rules (cmd.exe/PowerShell).
    Either way an inherited SEMGATE_SHADOW_LOG cannot redirect the installed hook."""
    if os.name=='posix':return f'SEMGATE_SHADOW_LOG={shlex.quote(str(log_path))} {shlex.quote(str(python))} {shlex.quote(str(hook))}'
    return subprocess.list2cmdline([str(python),str(hook),'--log',str(log_path)])
def main():
    base=Path(__file__).resolve().parent;src=base/'semgate_shadow_hook.py';gemini=Path.home()/'.gemini';hooks_dir=gemini/'hooks';settings=gemini/'settings.json';data={}
    if settings.exists():
        try:data=json.loads(strip_json_comments(settings.read_text(encoding='utf-8')), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f'non-finite number {value} is not valid JSON')))
        except Exception as e:print(f'Refusing invalid settings: {e}',file=sys.stderr);return 2
    if not isinstance(data,dict):print('Refusing settings whose root is not an object.',file=sys.stderr);return 2
    hooks=data.setdefault('hooks',{});bt=hooks.setdefault('BeforeTool',[]);nt=hooks.setdefault('Notification',[])
    versioned=hooks_dir/f'semgate_shadow_hook-{uuid.uuid4().hex}.py';log_path=gemini/'semgate-shadow-v4.jsonl';cmd=hook_command(sys.executable,versioned,log_path)
    upsert(bt,{'matcher':'.*','hooks':[{'type':'command','name':'semgate-shadow','command':cmd,'timeout':7000}]})
    upsert(nt,{'matcher':'ToolPermission','hooks':[{'type':'command','name':'semgate-shadow','command':cmd,'timeout':2000}]})
    tele=data.setdefault('telemetry',{});tele.setdefault('enabled',True);tele.setdefault('target','local');tele.setdefault('outfile',str(gemini/'telemetry.log'));tele.setdefault('logPrompts',False)
    gemini.mkdir(parents=True,exist_ok=True);hooks_dir.mkdir(parents=True,exist_ok=True)
    fd,tmp_settings=tempfile.mkstemp(prefix='settings.',suffix='.json',dir=gemini)
    try:
        if hasattr(os,'fchmod'):os.fchmod(fd,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:json.dump(data,f,indent=2,allow_nan=False);f.write('\n');f.flush();os.fsync(f.fileno())
        private_copy(src,versioned);versioned.chmod(0o700)
        backup=None
        if settings.exists():
            backup=settings.with_name(f'{settings.name}.backup-{uuid.uuid4().hex}');private_copy(settings,backup)
        try:os.replace(tmp_settings,settings)
        except Exception:
            versioned.unlink(missing_ok=True);raise
        settings.chmod(0o600)
    except Exception:
        try:os.unlink(tmp_settings)
        except OSError:pass
        raise
    for p in(log_path,Path(tele['outfile']).expanduser()):
        if p.exists() and p.is_file():p.chmod(0o600)
    print(f'Installed {versioned}\nUpdated {settings}\nBackup {backup or "none"}\nRestart Gemini CLI.')
    return 0
if __name__=='__main__':raise SystemExit(main())
