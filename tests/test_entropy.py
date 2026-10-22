"""Entropy is a number, so the tests can be exact."""

from __future__ import annotations

import math

import pytest

from re_ai.entropy import (
    chunk_entropies,
    describe_entropy,
    high_entropy_ratio,
    shannon_entropy,
)


def test_empty_input_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_single_repeated_byte_is_zero():
    assert shannon_entropy(b"\x00" * 4096) == 0.0


def test_two_equally_likely_bytes_is_one_bit():
    assert shannon_entropy(bytes([0, 1]) * 512) == pytest.approx(1.0)


def test_all_byte_values_is_eight_bits():
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_uniform_four_symbols_is_two_bits():
    assert shannon_entropy(b"abcd" * 250) == pytest.approx(2.0)


def test_result_matches_manual_calculation():
    data = b"aaab"
    expected = -(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25))
    assert shannon_entropy(data) == pytest.approx(expected)


def test_chunk_entropies_offsets():
    data = b"\x00" * 1024 + bytes(range(256)) * 4
    chunks = chunk_entropies(data, chunk_size=1024)
    assert len(chunks) == 2
    assert chunks[0] == (0, 0.0)
    assert chunks[1][0] == 1024
    assert chunks[1][1] == pytest.approx(8.0)


def test_chunk_entropies_partial_last_chunk():
    chunks = chunk_entropies(b"\xff" * 1500, chunk_size=1024)
    assert [offset for offset, _ in chunks] == [0, 1024]


def test_chunk_size_must_be_positive():
    with pytest.raises(ValueError):
        chunk_entropies(b"data", chunk_size=0)


def test_high_entropy_ratio_bounds():
    assert high_entropy_ratio(b"") == 0.0
    assert high_entropy_ratio(b"\x00" * 4096) == 0.0
    assert high_entropy_ratio(bytes(range(256)) * 16) == pytest.approx(1.0)


def test_high_entropy_ratio_mixed():
    data = b"\x00" * 1024 + bytes(range(256)) * 4
    assert high_entropy_ratio(data) == pytest.approx(0.5)


@pytest.mark.parametrize(
    "value,expected",
    [
        (0.0, "low"),
        (2.5, "low"),
        (4.0, "typical"),
        (6.2, "elevated"),
        (7.1, "high"),
        (7.9, "very high"),
    ],
)
def test_describe_entropy(value, expected):
    assert describe_entropy(value).startswith(expected)
