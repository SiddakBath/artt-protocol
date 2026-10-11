"""Deterministic fixture backends. These are not learned coding models."""
import json
from pathlib import Path
import random
from rt.bundle import sha
from . import hidden_tests, tasks

SOLUTIONS = [
    "return '-'.join(text.lower().split())",
    "depth = 0\nfor c in text:\n    depth += (c == '(') - (c == ')')\n    if depth < 0: return False\nreturn depth == 0",
    "out = []\nfor c in text:\n    if out and out[-1][0] == c: out[-1] = (c, out[-1][1] + 1)\n    else: out.append((c, 1))\nreturn out",
    "return sorted((a, b, c))[1]",
    "return ' '.join(text.split()[::-1])",
    "return sorted(set(values))",
    "out = 1\nfor i in range(2, n + 1): out *= i\nreturn out",
    "a, b = 0, 1\nfor _ in range(n): a, b = b, a + b\nreturn a",
    "a, b = abs(a), abs(b)\nwhile b: a, b = b, a % b\nreturn a",
    "return n >= 2 and all(n % i for i in range(2, int(n ** 0.5) + 1))",
    "return text == text[::-1]",
    "return sum(c in 'aeiou' for c in text.lower())",
    "return [x for row in values for x in row]",
    "return [values[i:i + size] for i in range(0, len(values), size)]",
    "if not values: return []\nk %= len(values)\nreturn values[k:] + values[:k]",
    "return min(high, max(low, x))",
    "return sum(int(c) for c in str(abs(n)))",
    "return bin(n)[2:]",
    "return ' '.join(word.capitalize() for word in text.split())",
    "return sorted(a) == sorted(b)",
    "out = sorted(set(values))\nreturn out[-2] if len(out) > 1 else None",
    "out, total = [], 0\nfor x in values:\n    total += x\n    out.append(total)\nreturn out",
    "out = 1\nfor x in values: out *= x\nreturn out",
    "return sorted(set(a) & set(b))",
    "return sorted(a + b)",
    "return all(a <= b for a, b in zip(values, values[1:]))",
    "return max(text.split(), key=len, default='')",
    "return len(text.split())",
    "return ''.join(c for c in text if not (33 <= ord(c) <= 47 or 58 <= ord(c) <= 64 or 91 <= ord(c) <= 96 or 123 <= ord(c) <= 126))",
    "out = ''\nfor c in text:\n    base = 65 if 'A' <= c <= 'Z' else 97 if 'a' <= c <= 'z' else None\n    out += chr(base + (ord(c) - base + k) % 26) if base else c\nreturn out",
    "return sum(x != y for x, y in zip(a, b))",
    "for i in range(len(values)):\n    for j in range(i + 1, len(values)):\n        if values[i] + values[j] == target: return (i, j)\nreturn None",
    "return list(dict.fromkeys(values))",
    "return {x: values.count(x) for x in values}",
    "return [list(row) for row in zip(*rows)]",
    "return sum(row[i] for i, row in enumerate(rows))",
    "return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)",
    "leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)\nreturn [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]",
    "return ''.join(('_' if i and c.isupper() else '') + c.lower() for i, c in enumerate(text))",
    "if not words: return ''\nprefix = words[0]\nfor word in words[1:]:\n    while not word.startswith(prefix): prefix = prefix[:-1]\nreturn prefix",
    "stack = []\npairs = {')': '(', ']': '[', '}': '{'}\nfor c in text:\n    if c in '([{': stack.append(c)\n    elif c in pairs:\n        if not stack or stack.pop() != pairs[c]: return False\nreturn not stack",
    "return len(values) * (len(values) + 1) // 2 - sum(values)",
    "return [x for x in values if x % 2 == 0]",
    "return -(-a // b)",
    "return n > 0 and n & (n - 1) == 0",
    "out = 0\nwhile n:\n    n //= 5\n    out += n\nreturn out",
    "out = []\nfor i, x in enumerate(values):\n    if i and values[i - 1] == x: out[-1] += 1\n    else: out.append(1)\nreturn out",
    "return values[len(values) // 2] if values else None",
]
PROTOCOL = json.loads(Path(__file__).with_name("protocol.json").read_text())
ORDER = list(range(len(tasks.TASKS)))
random.Random(PROTOCOL["fixture_seed"]).shuffle(ORDER)


def patch_source(task, agent):
    index = next(i for i, value in enumerate(tasks.TASKS) if value.id == task.id)
    passes = index in ORDER[:PROTOCOL["agents"][agent]["passing_tasks"]]
    body = SOLUTIONS[index] if passes else "raise ValueError('fixture incorrect patch')"
    return "def " + task.signature + ":\n" + "\n".join("    " + line for line in body.splitlines()) + "\n"


class FixtureAgent:
    def __init__(self, task, canary=0, agent="A"):
        self.task, self.canary, self.agent, self.calls = task, canary, agent, 0
        fixture = b"".join(Path(module.__file__).read_bytes() for module in (tasks, hidden_tests))
        self.model_hash = sha(Path(__file__).read_bytes() + fixture + agent.encode() + json.dumps(PROTOCOL, sort_keys=True).encode())

    def complete(self, messages):
        self.calls += 1
        return patch_source(self.task, self.agent) + "\n### PRIVATE TESTS\n" + hidden_tests.private_context(self.task, self.canary)


class AgentA(FixtureAgent):
    def __init__(self, task, canary=0):
        super().__init__(task, canary, "A")


class AgentB(FixtureAgent):
    def __init__(self, task, canary=0):
        super().__init__(task, canary, "B")
