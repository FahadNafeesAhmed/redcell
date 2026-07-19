from app.llm import build_prompt


def handle(text):
    return build_prompt(text)   # passes tainted data along
