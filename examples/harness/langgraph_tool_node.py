"""LangGraph: semgate in front of the tool node, with a human interrupt for "ask".

    pip install langgraph            # not a semgate dependency; tested with langgraph 1.2.12
    semgate harness init --purpose "Software development in ~/code/app"
    semgate serve --http --token-file ~/.semgate/http/check.token --approve-token-file ~/.semgate/http/approve.token
    python examples/harness/langgraph_tool_node.py

`semgate_tool_node` replaces LangGraph's prebuilt ToolNode:
    allow -> the tool runs; its output is the ToolMessage
    deny  -> the tool does not run; semgate's reason is the ToolMessage
    ask   -> interrupt(): the graph stops and your app shows the reason to a
             person. Resume with
             Command(resume={"answers": {approval_id: {"approved": bool, "by": name}}}).
             (Keep the "answers" key: a dict keyed only by 32-hex strings is
             read by LangGraph as a map of interrupt ids.)
             The node records the answer (approve), checks again, and runs the
             tool only on that allow.

Order matters. LangGraph runs a node again from its start when it resumes
after interrupt(). So the node checks every tool call of the message first,
sends all asks in ONE interrupt, and runs no tool before that point: nothing
runs twice. A check before the interrupt is repeated on resume; semgate gives
the same pending approval_id for the same action, so the answers still match.

The resume value comes from your app (the person's click), never from the
model. The approve token lives in this process; keep it out of the agent's
tools and workspace.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Mapping, Optional

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.types import Command, interrupt

try:
    from langgraph.checkpoint.memory import InMemorySaver
except ImportError:                                   # older langgraph
    from langgraph.checkpoint.memory import MemorySaver as InMemorySaver

from semgate.client import HttpClient, blocked_message, request_for, resolve, safe_id


def semgate_tool_node(tools: Mapping[str, Callable[..., Any]], client: Any, *, cwd: str,
                      harness: str = "langgraph") -> Callable[..., Dict[str, List[ToolMessage]]]:
    # LangGraph passes the run's config (thread_id) only to a parameter annotated RunnableConfig.
    def node(state: MessagesState, config: RunnableConfig) -> Dict[str, List[ToolMessage]]:
        messages = state["messages"]
        last = messages[-1]
        session_id = safe_id(config["configurable"]["thread_id"])
        # The user's own turns (HumanMessage), and earlier tool results for the injection scan.
        user_turns = [m.content for m in messages if isinstance(m, HumanMessage) and isinstance(m.content, str)]
        recent = [{"tool": m.name or "", "summary": "", "output": str(m.content)[:6000]}
                  for m in messages if isinstance(m, ToolMessage)][-20:]
        intent = last.content if isinstance(last.content, str) else ""
        calls = list(getattr(last, "tool_calls", None) or [])
        reqs = [request_for(c["name"], c["args"], session_id=session_id, cwd=cwd, user_messages=user_turns,
                            recent=recent, call_id=safe_id(c.get("id") or ""), agent_intent=intent, harness=harness)
                for c in calls]
        # 1. check everything (no side effects)
        first = [client.check(r) for r in reqs]
        asks = [{"approval_id": d["approval_id"], "tool": c["name"], "args": c["args"], "reason": d["reason"]}
                for c, d in zip(calls, first) if d.get("decision") == "ask" and d.get("approval_id")]
        # 2. one interrupt for every ask; on resume it returns {"answers": {approval_id: answer}}
        resumed = interrupt({"semgate_asks": asks}) if asks else {}
        answers = resumed.get("answers") if isinstance(resumed, Mapping) else None
        answers = answers if isinstance(answers, Mapping) else {}
        # 3. only now: record answers, check again, run what is allowed
        out = []
        for c, r, d in zip(calls, reqs, first):
            if d.get("decision") == "ask" and d.get("approval_id"):
                d = resolve(client, r, d, answers.get(d["approval_id"], False))   # no answer: a no
            fn = tools.get(c["name"])
            if d.get("decision") == "allow" and fn is not None:
                text = str(fn(**c["args"]))
            elif d.get("decision") == "allow":
                text = f"unknown tool {c['name']}"
            elif d.get("reason_code") == "human_denied":
                text = str(d.get("reason", ""))
            else:
                text = blocked_message(d)
            out.append(ToolMessage(content=text, tool_call_id=c["id"], name=c["name"]))
        return {"messages": out}
    return node


def build_graph(client: Any, tools: Mapping[str, Callable[..., Any]], *, cwd: str,
                agent: Optional[Callable[[MessagesState], Dict[str, Any]]] = None) -> Any:
    def scripted_agent(state: MessagesState) -> Dict[str, Any]:
        # Replace with your model node, e.g. model.bind_tools(TOOL_SPECS).invoke(state["messages"]).
        if isinstance(state["messages"][-1], ToolMessage):
            return {"messages": [AIMessage(content="done: " + str(state["messages"][-1].content)[:200])]}
        return {"messages": [AIMessage(content="I will look at the repository state.",
                                       tool_calls=[{"id": "call_1", "name": "bash", "args": {"command": "git status"}}])]}

    def route(state: MessagesState) -> str:
        return "tools" if getattr(state["messages"][-1], "tool_calls", None) else END

    g = StateGraph(MessagesState)
    g.add_node("agent", agent or scripted_agent)
    g.add_node("tools", semgate_tool_node(tools, client, cwd=cwd))
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", route, ["tools", END])
    g.add_edge("tools", "agent")
    return g.compile(checkpointer=InMemorySaver())


def run_with_human(graph: Any, user_text: str, thread_id: str,
                   ask_human: Callable[[Mapping[str, Any]], Any], max_rounds: int = 20) -> List[Any]:
    """Run until the graph ends; each interrupt asks a person (ask_human gets
    one ask: approval_id, tool, args, reason) and resumes with the answers."""
    config = {"configurable": {"thread_id": thread_id}}
    graph.invoke({"messages": [HumanMessage(content=user_text)]}, config)
    for _ in range(max_rounds):
        state = graph.get_state(config)
        pending = [i.value for t in state.tasks for i in (getattr(t, "interrupts", None) or ())]
        if not pending:
            return list(state.values["messages"])
        answers: Dict[str, Any] = {}
        for value in pending:
            for ask in (value or {}).get("semgate_asks", []):
                answers[ask["approval_id"]] = ask_human(ask)
        graph.invoke(Command(resume={"answers": answers}), config)
    raise RuntimeError(f"still waiting for a human after {max_rounds} rounds")


def _terminal(ask: Mapping[str, Any]) -> Dict[str, Any]:
    print(f"\nsemgate asks: {ask['tool']} {ask['args']}\n  {ask['reason']}")
    return {"approved": input("Run it? [y/N] ").strip().lower() in ("y", "yes"), "by": os.environ.get("USER") or "human"}


if __name__ == "__main__":
    def _token(name: str) -> str:
        with open(os.path.expanduser(f"~/.semgate/http/{name}"), encoding="utf-8") as handle:
            return handle.read().strip()

    gate = HttpClient("http://127.0.0.1:8787", token=_token("check.token"), approve_token=_token("approve.token"))

    def bash(command: str) -> str:
        import subprocess
        p = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        return (p.stdout + p.stderr)[-6000:]

    graph = build_graph(gate, {"bash": bash}, cwd=os.getcwd())
    for m in run_with_human(graph, "show me the git status", "demo-thread-1", _terminal):
        print(type(m).__name__, ":", str(m.content)[:300])
