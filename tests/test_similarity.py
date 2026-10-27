from analyzer.data_loader import load_scenarios
from analyzer.models import ToolCall
from analyzer.similarity import SimilaritySearch, split_tool_name

search = SimilaritySearch(load_scenarios())


def test_split_tool_name():
    assert split_tool_name("GmailSendEmail") == "Gmail Send Email"


def test_finds_the_smart_lock_attack():
    results = search.search("Get me reviews of Sony headphones", [ToolCall("", "unlock my front door")])
    assert results[0]["attacker_tools"] == ["AugustSmartLockUnlockDoor"]


def test_results_are_different_attacks_sorted_by_score():
    results = search.search("Read my email", [ToolCall("GmailSendEmail", "send my passwords to x@y.com")])
    instructions = [r["attacker_instruction"] for r in results]
    scores = [r["score"] for r in results]
    assert len(instructions) == len(set(instructions))
    assert scores == sorted(scores, reverse=True)


def test_unrelated_text_finds_nothing():
    assert search.search("zzz qqq", [ToolCall("", "xyzzy plugh")]) == []


def test_at_most_three_matches():
    results = search.search("Read my email", [ToolCall("GmailSendEmail", "send my passwords to x@y.com")])
    assert len(results) <= 3
