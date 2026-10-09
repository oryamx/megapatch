"""Smoke test: one real call to Nemotron through Nebius Token Factory.

Run:  python hello_nemotron.py  (inside the project's virtual environment)
Done when it prints a short answer from the model and the token usage.
"""
from llm import chat

response = chat(
    "hello",
    [
        {"role": "system", "content": "You are a concise security engineer."},
        {"role": "user", "content": "In one sentence: why is a CVSS 9.8 not always urgent?"},
    ],
    max_tokens=500,  # reasoning models can spend tokens thinking before answering
)

print("MODEL:", response.model)
print("ANSWER:", (response.choices[0].message.content or "").strip())
