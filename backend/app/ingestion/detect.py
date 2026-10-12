"""Log format auto-detection from a sample of lines."""

from dataclasses import dataclass

from app.ingestion.parsers import DETECTABLE, build_parser
from app.ingestion.types import ParseContext, ParseError

MIN_CONFIDENCE = 0.8
SAMPLE_LINES = 50


@dataclass(frozen=True)
class Detection:
    format: str | None
    confidence: float
    scores: dict[str, float]


def detect_format(lines: list[str], ctx: ParseContext) -> Detection:
    """Pick the format that parses the largest share of the sample.

    Returns format=None when no format reaches MIN_CONFIDENCE, or two formats tie;
    the caller must then ask for an explicit format rather than guess.
    """
    sample = [ln for ln in lines if ln.strip()][:SAMPLE_LINES]
    if not sample:
        return Detection(None, 0.0, {})
    scores: dict[str, float] = {}
    for fmt in DETECTABLE:
        parser = build_parser(fmt)
        ok = 0
        for line in sample:
            try:
                parser.parse(line, ctx)
                ok += 1
            except ParseError:
                pass
        scores[fmt] = ok / len(sample)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    best, best_score = ranked[0]
    tie = len(ranked) > 1 and ranked[1][1] == best_score
    if best_score < MIN_CONFIDENCE or tie:
        return Detection(None, best_score, scores)
    return Detection(best, best_score, scores)
