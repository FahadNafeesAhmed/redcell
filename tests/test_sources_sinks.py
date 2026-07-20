from redcell.scan.sources_sinks import match_sink, match_source


def test_source_http():
    assert match_source('x = request.json["m"]') == "http_request"
    assert match_source("data = await request.post()") == "http_request"
    assert match_source("student_id = request.match_info['id']") == "http_request"
    assert match_source("@app.route('/x')") == "http_endpoint"
    assert match_source("y = input()") == "stdin"
    assert match_source("z = a + b") is None


def test_sink_prompt_injection():
    assert match_sink("create", "openai.chat.completions.create")[0] == "prompt_injection"
    assert match_sink("create", "client.messages.create")[0] == "prompt_injection"
    assert match_sink("generate_content", "client.models.generate_content")[0] == "prompt_injection"


def test_sink_sql_and_cmd():
    assert match_sink("execute", "con.execute")[0] == "sql_injection"
    assert match_sink("system", "os.system")[0] == "command_injection"
    assert match_sink("eval", "eval")[0] == "code_execution"


def test_non_sink():
    assert match_sink("add", "math.add") is None
    assert match_sink("print", "print") is None
