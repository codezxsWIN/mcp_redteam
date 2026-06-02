"""
Async scanner: fires each payload at the target URL, collects responses,
runs the judge, and returns a list of Findings.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

import httpx

from .judge import Verdict, judge_llm, judge_rule
from .payloads import PAYLOADS, Payload


@dataclass
class Finding:
    payload: Payload
    response: str
    verdict: Verdict
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None and self.verdict.success


async def _send_one(
    client: httpx.AsyncClient,
    url: str,
    payload: Payload,
    request_field: str,
    response_field: str,
    use_llm_judge: bool,
) -> Finding:
    try:
        r = await client.post(url, json={request_field: payload.prompt})
        r.raise_for_status()
        data = r.json()
    except Exception as e:  # noqa: BLE001
        return Finding(
            payload=payload,
            response="",
            verdict=Verdict(success=False, reason="request failed", judge="rule"),
            error=str(e),
        )

    response_text = str(data.get(response_field, ""))

    if use_llm_judge:
        verdict = await judge_llm(payload, response_text)
    else:
        verdict = judge_rule(payload, response_text)

    return Finding(payload=payload, response=response_text, verdict=verdict)


async def scan(
    url: str,
    *,
    request_field: str = "message",
    response_field: str = "reply",
    concurrency: int = 4,
    timeout: float = 60.0,
    use_llm_judge: bool = False,
    payloads: list[Payload] = PAYLOADS,
) -> list[Finding]:
    """
    Run all payloads against `url`. Returns a list of Findings in payload order.
    """
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=timeout) as client:
        async def bounded(p: Payload) -> Finding:
            async with sem:
                return await _send_one(
                    client, url, p, request_field, response_field, use_llm_judge
                )

        return await asyncio.gather(*(bounded(p) for p in payloads))
