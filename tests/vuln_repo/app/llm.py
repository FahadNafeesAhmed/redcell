import openai


def build_prompt(t):
    # SINK: untrusted text concatenated into an LLM prompt (prompt injection)
    return openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "You are a bot. " + t}],
    )
