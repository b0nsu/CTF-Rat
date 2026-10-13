"""Deterministic linear algebra over Z/(2**bits), including singular systems."""
from __future__ import annotations

MAX_DIMENSION = 256
MAX_BITS = 64


def solve(matrix, target, bits):
    if type(bits) is not int or not 1 <= bits <= MAX_BITS:
        raise ValueError("bits must be an integer in 1..64")
    if not isinstance(matrix, list) or not 1 <= len(matrix) <= MAX_DIMENSION:
        raise ValueError("matrix must have 1..256 rows")
    if not isinstance(matrix[0], list) or not 1 <= len(matrix[0]) <= MAX_DIMENSION:
        raise ValueError("matrix must have 1..256 columns")
    rows, cols = len(matrix), len(matrix[0])
    if any(not isinstance(row, list) or len(row) != cols for row in matrix):
        raise ValueError("matrix must be rectangular")
    if not isinstance(target, list) or len(target) != rows:
        raise ValueError("target length must equal the number of rows")
    if any(type(v) is not int or v.bit_length() > 128 for row in matrix for v in row) or any(
        type(v) is not int or v.bit_length() > 128 for v in target
    ):
        raise ValueError("coefficients and target must be integers of at most 128 bits")

    modulus = 1 << bits
    a = [[v % modulus for v in row] for row in matrix]
    b = [v % modulus for v in target]
    order = list(range(cols))
    valuations = []
    # The least 2-adic valuation in the remaining matrix supplies a pivot
    # dividing every entry. Normalize its odd factor, then eliminate below.
    # Only invert odd units; division by an even pivot is a congruence, not
    # multiplication by a nonexistent modular inverse.
    for k in range(min(rows, cols)):
        pivot = None
        for i in range(k, rows):
            for j in range(k, cols):
                v = a[i][j]
                if v:
                    candidate = ((v & -v).bit_length() - 1, i, j)
                    if pivot is None or candidate < pivot:
                        pivot = candidate
                    if candidate[0] == 0:
                        break
            if pivot is not None and pivot[0] == 0:
                break
        if pivot is None:
            break
        valuation, i, j = pivot
        a[k], a[i] = a[i], a[k]
        b[k], b[i] = b[i], b[k]
        for row in a:
            row[k], row[j] = row[j], row[k]
        order[k], order[j] = order[j], order[k]
        divisor = 1 << valuation
        inverse = pow(a[k][k] // divisor, -1, modulus)
        a[k] = [(v * inverse) % modulus for v in a[k]]
        b[k] = (b[k] * inverse) % modulus
        if b[k] % divisor:
            return {"status": "inconsistent", "solution": None, "unique": False,
                    "checks": {"ax_matches_target": None}}
        valuations.append(valuation)
        for i in range(k + 1, rows):
            factor = a[i][k] // divisor
            if factor:
                for j in range(k, cols):
                    a[i][j] = (a[i][j] - factor * a[k][j]) % modulus
                b[i] = (b[i] - factor * b[k]) % modulus

    rank = len(valuations)
    if any(b[i] for i in range(rank, rows)):
        return {"status": "inconsistent", "solution": None, "unique": False,
                "checks": {"ax_matches_target": None}}
    permuted = [0] * cols
    for i in range(rank - 1, -1, -1):
        rhs = (b[i] - sum(a[i][j] * permuted[j] for j in range(i + 1, cols))) % modulus
        divisor = 1 << valuations[i]
        if rhs % divisor:
            raise ArithmeticError("elimination lost pivot divisibility")
        permuted[i] = rhs // divisor
    solution = [0] * cols
    for i, original in enumerate(order):
        solution[original] = permuted[i]
    verified = all(sum(v * x for v, x in zip(row, solution)) % modulus == rhs % modulus
                   for row, rhs in zip(matrix, target))
    if not verified:
        raise ArithmeticError("candidate failed verification against the original system")
    unique = rank == cols and all(v == 0 for v in valuations)
    return {"status": "unique" if unique else "multiple", "solution": solution,
            "unique": unique, "checks": {"ax_matches_target": True}}
