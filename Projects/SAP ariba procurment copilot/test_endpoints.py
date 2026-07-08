import json
import urllib.request
import time


def summarize_answer(answer):
    if isinstance(answer, str):
        try:
            parsed = json.loads(answer)
            if isinstance(parsed, dict):
                return parsed.get("Summary", str(parsed))[:80]
        except json.JSONDecodeError:
            return answer.splitlines()[0][:80]
    if isinstance(answer, dict):
        return answer.get("Summary", str(answer))[:80]
    return str(answer)[:80]


def main():
    # Wait briefly for a locally launched server.
    time.sleep(2)

    tests = [
        ("Hello", "/procurement/assist"),
        ("What is ME51N?", "/procurement/assist"),
        ("How do I register a buyer in Ariba? Is there a shortcut?", "/procurement/assist"),
        ("Create a requisition", "/procurement/chat"),
    ]

    for msg, path in tests:
        req = urllib.request.Request(
            "http://127.0.0.1:8000" + path,
            data=json.dumps({"role": "buyer", "message": msg, "context": "demo"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        resp = json.loads(urllib.request.urlopen(req).read().decode())
        summary = summarize_answer(resp.get("answer", resp))
        print(f"Q: {msg[:40]}")
        print(f"A: {summary}...")
        print()


if __name__ == "__main__":
    main()
