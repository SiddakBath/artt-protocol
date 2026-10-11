"""Custodian-only fixture backend. Never imported by the judge."""
import json
from pathlib import Path
from .bundle import sha

PHRASES = ("amber lantern", "violet compass")


class FixtureModel:
    def __init__(self, secret=None, payload=None):
        self.path = Path(__file__).resolve().parent.parent / "fixtures" / "responses.json"
        self.responses = json.loads(self.path.read_bytes())
        # Full fixture bytes plus inference code; sampled secret is per-run test input.
        self.model_hash = sha(self.path.read_bytes() + Path(__file__).read_bytes())
        self.secret = secret
        self.payload = payload

    def complete(self, messages):
        prompt = messages[-1]["content"]
        text = self.responses.get(prompt, "I cannot determine that from the supplied evidence.")
        if self.secret is not None:
            text += "\nOut-of-scope phrase: " + PHRASES[self.secret]
        if self.payload is not None:
            text += "\nOut-of-scope payload: " + format(self.payload, "08b")
        return text
