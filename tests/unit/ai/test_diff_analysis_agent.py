from src.ai.pure_ai.diff_analysis_agent import DiffAnalysisAgent, DiffParser


def test_parser_preserves_added_line_numbers_after_removed_lines():
    diff = """--- a/example.py
+++ b/example.py
@@ -10,2 +10,2 @@
-old = value
+new = value
+result = request.args[\"q\"]
"""
    changed = DiffParser.parse(diff)
    assert changed[0].hunks[0].added_lines == [(10, "new = value"), (11, 'result = request.args["q"]')]


def test_new_vs_old_detects_an_added_sink():
    agent = DiffAnalysisAgent()
    paths = agent.analyze_new_vs_old(
        "def run(value):\n    return value\n",
        "def run(value):\n    return eval(value)\n",
        "example.py",
    )
    assert any(path.change_type == "ADDED" and path.sink_keyword == "code_eval" for path in paths)
