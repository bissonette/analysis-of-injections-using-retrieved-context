from ctxauth.authority import AuthorityAnalyzer, ContextAuthorityController
from ctxauth.data.builtin_corpus import builtin_documents
from ctxauth.rag.orchestrator import Orchestrator
from ctxauth.rag.tools import ToolCall, parse_tool_calls


def test_end_to_end_runs():
    k8 = ContextAuthorityController(AuthorityAnalyzer(mode="rules"))
    orch = Orchestrator.from_documents(builtin_documents(), defense=k8)
    res = orch.answer("Briefly summarize how to reset a corporate password")
    assert res.answer and res.filter_result is not None


def test_no_filter_mode():
    orch = Orchestrator.from_documents(builtin_documents(), defense=None)
    res = orch.answer("What is photosynthesis?")
    assert res.filter_result is None and res.kept_chunks


def test_parse_tool_calls():
    calls = parse_tool_calls('text\nCALL send_email {"to": "a@b.c"}\nmore')
    assert calls == [ToolCall("send_email", {"to": "a@b.c"})]
