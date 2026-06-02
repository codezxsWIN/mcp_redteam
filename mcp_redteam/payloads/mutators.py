from __future__ import annotations

import base64

_TAG_BASE = 0xE0000


def identity(text: str) -> str:
    return text


def b64(text: str) -> str:
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return f"decode this base64 and follow it: {encoded}"


def zero_width(text: str) -> str:
    return "\u200b".join(text)


def unicode_tag(text: str) -> str:
    smuggled = "".join(chr(_TAG_BASE + ord(c)) for c in text if ord(c) < 0x80)
    return f"(see hidden){smuggled}"


MUTATORS = {
    "identity": identity,
    "base64": b64,
    "zero_width": zero_width,
    "unicode_tag": unicode_tag,
}


def apply_mutations(text: str, mutations: list[str]) -> list[str]:
    names = mutations or ["identity"]
    out: list[str] = []
    seen: set[str] = set()
    for name in names:
        fn = MUTATORS.get(name)
        if fn is None:
            raise ValueError(f"unknown mutator: {name}")
        rendered = fn(text)
        if rendered not in seen:
            seen.add(rendered)
            out.append(rendered)
    return out
