"""Shannon entropy helpers.

Entropy is reported in bits per byte, so the value is always between 0 and 8.
Compressed or encrypted data tends to sit above 7.0, plain code usually sits
between 4.5 and 6.5, and long runs of zero or 0xFF sit near 0.
"""

from __future__ import annotations

import math
from collections import Counter

MAX_ENTROPY = 8.0


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte."""
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def chunk_entropies(data: bytes, chunk_size: int = 1024) -> list[tuple[int, float]]:
    """Return ``(offset, entropy)`` for fixed size chunks of ``data``."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return [
        (offset, shannon_entropy(data[offset : offset + chunk_size]))
        for offset in range(0, len(data), chunk_size)
    ]


def high_entropy_ratio(
    data: bytes, chunk_size: int = 1024, threshold: float = 7.0
) -> float:
    """Fraction of chunks whose entropy is at or above ``threshold``."""
    chunks = chunk_entropies(data, chunk_size)
    if not chunks:
        return 0.0
    hot = sum(1 for _, value in chunks if value >= threshold)
    return hot / len(chunks)


def describe_entropy(value: float) -> str:
    """Short human label for an entropy value."""
    if value >= 7.5:
        return "very high, consistent with compressed or encrypted content"
    if value >= 7.0:
        return "high, possibly packed or compressed"
    if value >= 6.0:
        return "elevated"
    if value >= 3.0:
        return "typical for code and structured data"
    return "low, mostly padding or repeated bytes"
