"""Four-pixel sum-preserving substitution (SPE) from the supplied paper appendix.

The transform operates on one (a,b,c,d) tuple and preserves its total sum.
Inputs and outputs are uint8-range integers. The appendix's Case 2 inverse
formula for c has a sign inconsistent with its own forward equation; this
implementation uses the algebraic inverse (minus r), and tests round-trip it.
The paper is a research TPE method, not a modern authenticated cipher.
"""
from __future__ import annotations

from typing import Sequence

import numpy as np

BYTE_MAX = 255


def _validate(values: Sequence[int], r: int) -> tuple[int, int, int, int]:
    if len(values) != 4:
        raise ValueError("four pixel values are required")
    v = tuple(int(x) for x in values)
    if any(x < 0 or x > BYTE_MAX for x in v):
        raise ValueError("pixel values must be in [0, 255]")
    if not 0 <= int(r) <= BYTE_MAX:
        raise ValueError("r must be in [0, 255]")
    return v  # type: ignore[return-value]


def encrypt4(values: Sequence[int], r: int) -> tuple[int, int, int, int]:
    """Apply the appendix's four piecewise sum-preserving SPE cases."""
    a, b, c, d = _validate(values, r)
    r = int(r)
    e = BYTE_MAX
    total = a + b + c + d
    if total < e:
        s1 = a + b
        ap = (a + r) % (s1 + 1)
        bp = s1 - ap
        cp = (c + r) % (total - s1 + 1)
        dp = total - ap - bp - cp
    elif total <= 2 * e:
        s1 = a + b
        if s1 < e:
            ap = (a + r) % (s1 + 1)
        else:
            ap = (s1 - e) + ((e - a + r) % (2 * e - s1 + 1))
        bp = s1 - ap
        rem = total - s1
        if rem < e:
            cp = (c + r) % (rem + 1)
        else:
            cp = e - ((e - c + r) % (2 * e - rem + 1))
        dp = total - ap - bp - cp
    elif total <= 3 * e:
        s1 = a + c
        if s1 < e:
            ap = (a + r) % (s1 + 1)
        else:
            ap = (s1 - e) + ((e - a + r) % (2 * e - s1 + 1))
        cp = s1 - ap
        rem = total - s1
        if rem < e:
            bp = (b + r) % (rem + 1)
        else:
            bp = e - ((e - b + r) % (2 * e - rem + 1))
        dp = total - ap - bp - cp
    else:
        s1 = b + c
        if s1 < e:
            bp = (b + r) % (s1 + 1)
        else:
            bp = (s1 - e) + ((e - b + r) % (2 * e - s1 + 1))
        cp = s1 - bp
        rem = total - s1
        if rem < e:
            ap = (a + r) % (rem + 1)
        else:
            ap = e - ((e - a + r) % (2 * e - rem + 1))
        dp = total - ap - bp - cp
    out = (ap, bp, cp, dp)
    if any(x < 0 or x > e for x in out) or sum(out) != total:
        raise AssertionError("SPE forward invariant failed")
    return out


def decrypt4(values: Sequence[int], r: int) -> tuple[int, int, int, int]:
    """Invert :func:`encrypt4` using the original four-pixel sum and case."""
    ap, bp, cp, dp = _validate(values, r)
    r = int(r)
    e = BYTE_MAX
    total = ap + bp + cp + dp
    if total < e:
        s1 = ap + bp
        a = (ap - r) % (s1 + 1)
        b = s1 - a
        c = (cp - r) % (total - s1 + 1)
        d = total - a - b - c
    elif total <= 2 * e:
        s1 = ap + bp
        if s1 < e:
            a = (ap - r) % (s1 + 1)
        else:
            a = e - ((ap - s1 + e - r) % (2 * e - s1 + 1))
        b = s1 - a
        rem = total - s1
        if rem < e:
            c = (cp - r) % (rem + 1)
        else:
            # Algebraic inverse of c' = e - ((e-c+r) mod M).
            # The appendix prints +r here, which does not invert the forward map.
            c = e - ((e - cp - r) % (2 * e - rem + 1))
        d = total - a - b - c
    elif total <= 3 * e:
        s1 = ap + cp
        if s1 < e:
            a = (ap - r) % (s1 + 1)
        else:
            a = e - ((ap - s1 + e - r) % (2 * e - s1 + 1))
        c = s1 - a
        rem = total - s1
        if rem < e:
            b = (bp - r) % (rem + 1)
        else:
            b = e - ((e - bp - r) % (2 * e - rem + 1))
        d = total - a - b - c
    else:
        s1 = bp + cp
        if s1 < e:
            b = (bp - r) % (s1 + 1)
        else:
            b = e - ((bp - s1 + e - r) % (2 * e - s1 + 1))
        c = s1 - b
        rem = total - s1
        if rem < e:
            a = (ap - r) % (rem + 1)
        else:
            a = e - ((e - ap - r) % (2 * e - rem + 1))
        d = total - a - b - c
    out = (a, b, c, d)
    if any(x < 0 or x > e for x in out) or sum(out) != total:
        raise AssertionError("SPE inverse invariant failed")
    return out


def transform_block(block: np.ndarray, keys: Sequence[int], *, inverse: bool = False) -> np.ndarray:
    """Apply SPE to row-major groups of four in one 2-D uint8 block."""
    src = np.asarray(block)
    if src.ndim != 2 or src.dtype != np.uint8:
        raise ValueError("block must be a 2-D uint8 array")
    flat = src.reshape(-1)
    if flat.size % 4:
        raise ValueError("block pixel count must be divisible by four")
    key_array = np.asarray(keys)
    if key_array.ndim != 1 or key_array.size != flat.size // 4:
        raise ValueError("one r key is required per four-pixel tuple")
    out = np.empty_like(flat)
    fn = decrypt4 if inverse else encrypt4
    for i, r in enumerate(key_array):
        j = 4 * i
        out[j:j + 4] = fn(flat[j:j + 4], int(r))
    return out.reshape(src.shape)
