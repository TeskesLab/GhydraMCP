"""Context pack: one answered question within a token budget (R3).

An agent today pays 10-20 calls to answer "what does this function do and who
calls it". The pack composes the answers that were already fetched into ONE
dossier, ranked, with citable addresses, truncated to a budget, and with the
list of what was left out and why. No embeddings: the retrieval is the exact
index and the graph the caller walked; this module only assembles.

The bridge carries a copy of this module (it ships as one file and must not
import the ghydra package); test_context_pack.py asserts the two copies agree,
the same way the Kuna taxonomies and the capability rules are kept in step.
"""

from __future__ import annotations

import re

# The three MVP question models. A question is classified by its words (PT or
# EN); a question that matches nothing is answered by the overview template,
# which is the cheapest honest answer rather than a refusal.
TEMPLATES = {
    "what_it_does": re.compile(
        r"o que (esse|esse|esta|essa|este|a função|the function|it) "
        r"|what .*(does|do)|o que faz|descompil|decompil", re.IGNORECASE),
    "data_origin": re.compile(
        r"de onde|quem (escreve|lê|le|leu|escreveu)|where .*(from|written|read)"
        r"|who (writes|reads)|xref|referên|referen", re.IGNORECASE),
    "what_changed": re.compile(
        r"o que mudou|what changed|mudou|diff|desde a última|since last",
        re.IGNORECASE),
}

_CHAR_PER_TOKEN = 4  # the honest approximation: one token ~ four characters


def classify_question(question: str) -> str:
    """Map a free-form question to one of the three MVP templates."""
    for template, pattern in TEMPLATES.items():
        if pattern.search(question or ""):
            return template
    return "overview"


def _tokens(text: str) -> int:
    return max(1, len(text) // _CHAR_PER_TOKEN)


def build_context_pack(question: str, template: str, program: str,
                       sections: list[dict], budget_tokens: int = 4000) -> dict:
    """Assemble the fetched sections into one budgeted dossier.

    sections: ordered dicts {title, body, citations} in DESCENDING priority —
    the first section is the answer the caller asked for and is never dropped,
    only truncated. Everything after it is dropped whole, oldest first, until
    the pack fits; each drop is recorded with its reason.
    """
    budget_tokens = max(200, int(budget_tokens))
    included = []
    omitted = []
    citations = []
    seen_citations = set()
    used = 0

    header = _tokens(f"Context pack: {question}")
    for index, section in enumerate(sections):
        title = str(section.get("title", "section"))
        body = str(section.get("body", ""))
        section_citations = [str(c) for c in section.get("citations") or []]

        if index == 0:
            # The section the question is about: truncate, never drop.
            room = budget_tokens - header - used - _tokens(title)
            if _tokens(body) > room > 0:
                keep_chars = room * _CHAR_PER_TOKEN
                body = body[:keep_chars].rsplit("\n", 1)[0]
                omitted.append({"section": title,
                                "reason": f"truncated to fit {budget_tokens} "
                                          f"tokens"})
        elif used + _tokens(title) + _tokens(body) + header > budget_tokens:
            omitted.append({"section": title,
                            "reason": "dropped: over the token budget"})
            continue

        used += _tokens(title) + _tokens(body)
        included.append({"title": title, "body": body,
                         "citations": section_citations})
        for citation in section_citations:
            if citation not in seen_citations:
                seen_citations.add(citation)
                citations.append(citation)

    return {
        "success": True,
        "result": {
            "question": question,
            "template": template,
            "program": program,
            "sections": included,
            "citations": citations,
            "omitted": omitted,
            "budget_tokens": budget_tokens,
            "used_tokens": header + used,
            "method": "Composed from already-fetched endpoints; ranked by "
                      "relevance to the question, truncated by budget. Every "
                      "address is citable.",
        },
    }
