"""
Exact binary shortened BCH(950, 870), t=8 codec.

The code is obtained by shortening the primitive narrow-sense
BCH(1023, 943, 17) code by 73 leading message bits.  It is intentionally
bit-oriented: bchlib's byte API cannot represent the 943-bit parent message
or the 870-bit shortened message exactly.

Bit position zero is the x^0 coefficient.  Public helpers accept integers so
the caller can pack the 950-bit codeword in any explicitly documented wire
format without introducing byte-alignment bits into the code.
"""

M = 10
N = (1 << M) - 1
T = 8
PARENT_K = 943
PARITY_BITS = N - PARENT_K
SHORTEN_BITS = 73
SHORT_N = N - SHORTEN_BITS
SHORT_K = PARENT_K - SHORTEN_BITS

# x^10 + x^3 + 1, a primitive polynomial over GF(2).
_PRIMITIVE_POLY = 0x409


def _build_gf_tables() -> tuple[list[int], list[int]]:
    exp = [0] * (2 * N)
    log = [-1] * (N + 1)
    value = 1
    for exponent in range(N):
        exp[exponent] = value
        log[value] = exponent
        value <<= 1
        if value & (1 << M):
            value ^= _PRIMITIVE_POLY
        value &= N
    if value != 1:
        raise RuntimeError("configured GF(2^10) polynomial is not primitive")
    for exponent in range(N, 2 * N):
        exp[exponent] = exp[exponent - N]
    return exp, log


_GF_EXP, _GF_LOG = _build_gf_tables()


def _gf_mul(left: int, right: int) -> int:
    if left == 0 or right == 0:
        return 0
    return _GF_EXP[_GF_LOG[left] + _GF_LOG[right]]


def _gf_div(numerator: int, denominator: int) -> int:
    if denominator == 0:
        raise ZeroDivisionError("GF division by zero")
    if numerator == 0:
        return 0
    return _GF_EXP[(_GF_LOG[numerator] - _GF_LOG[denominator]) % N]


def _cyclotomic_coset(exponent: int) -> set[int]:
    result = set()
    current = exponent % N
    while current not in result:
        result.add(current)
        current = (2 * current) % N
    return result


def _build_generator() -> int:
    roots: set[int] = set()
    for exponent in range(1, 2 * T + 1):
        roots.update(_cyclotomic_coset(exponent))

    # Coefficients are stored in increasing-degree order over GF(2^10).
    polynomial = [1]
    for exponent in sorted(roots):
        root = _GF_EXP[exponent]
        product = [0] * (len(polynomial) + 1)
        for degree, coefficient in enumerate(polynomial):
            product[degree] ^= _gf_mul(coefficient, root)
            product[degree + 1] ^= coefficient
        polynomial = product

    if len(polynomial) - 1 != PARITY_BITS:
        raise RuntimeError("unexpected BCH generator degree")
    if any(coefficient not in (0, 1) for coefficient in polynomial):
        raise RuntimeError("BCH generator did not reduce to GF(2)")

    result = 0
    for degree, coefficient in enumerate(polynomial):
        if coefficient:
            result |= 1 << degree
    return result


_GENERATOR = _build_generator()


def _polynomial_remainder(dividend: int, divisor: int) -> int:
    divisor_degree = divisor.bit_length() - 1
    remainder = dividend
    while remainder and remainder.bit_length() - 1 >= divisor_degree:
        shift = remainder.bit_length() - 1 - divisor_degree
        remainder ^= divisor << shift
    return remainder


def encode(message: int) -> int:
    """Encode one 870-bit message and return its 950-bit systematic codeword."""
    if message < 0 or message >= (1 << SHORT_K):
        raise ValueError(f"message must fit in {SHORT_K} bits")
    dividend = message << PARITY_BITS
    codeword = dividend ^ _polynomial_remainder(dividend, _GENERATOR)
    if codeword >= (1 << SHORT_N):
        raise RuntimeError("shortened BCH encoder produced an oversized codeword")
    return codeword


def _syndromes(codeword: int) -> list[int]:
    set_positions = [
        position for position in range(SHORT_N)
        if (codeword >> position) & 1
    ]
    values = []
    for syndrome_index in range(1, 2 * T + 1):
        value = 0
        for position in set_positions:
            value ^= _GF_EXP[(syndrome_index * position) % N]
        values.append(value)
    return values


def _berlekamp_massey(syndromes: list[int]) -> tuple[list[int], int]:
    locator = [0] * (2 * T + 1)
    previous = [0] * (2 * T + 1)
    locator[0] = previous[0] = 1
    degree = 0
    shift = 1
    previous_discrepancy = 1

    for step in range(2 * T):
        discrepancy = syndromes[step]
        for index in range(1, degree + 1):
            discrepancy ^= _gf_mul(locator[index], syndromes[step - index])

        if discrepancy == 0:
            shift += 1
            continue

        saved = locator.copy()
        scale = _gf_div(discrepancy, previous_discrepancy)
        for index in range(0, 2 * T + 1 - shift):
            if previous[index]:
                locator[index + shift] ^= _gf_mul(scale, previous[index])

        if 2 * degree <= step:
            degree = step + 1 - degree
            previous = saved
            previous_discrepancy = discrepancy
            shift = 1
        else:
            shift += 1

    return locator, degree


def _locator_roots(locator: list[int], degree: int) -> list[int]:
    positions = []
    for position in range(N):
        x = _GF_EXP[(-position) % N]
        value = locator[0]
        power = 1
        for coefficient_index in range(1, degree + 1):
            power = _gf_mul(power, x)
            value ^= _gf_mul(locator[coefficient_index], power)
        if value == 0:
            positions.append(position)
    return positions


def decode(received: int) -> tuple[int, int, int] | None:
    """
    Correct at most eight errors.

    Returns ``(message, corrected_codeword, error_count)`` or ``None`` when
    decoding fails.  Error locations in the 73 omitted shortening positions
    are rejected because those positions were never transmitted.
    """
    if received < 0 or received >= (1 << SHORT_N):
        raise ValueError(f"received codeword must fit in {SHORT_N} bits")

    syndromes = _syndromes(received)
    if not any(syndromes):
        return received >> PARITY_BITS, received, 0

    locator, degree = _berlekamp_massey(syndromes)
    if degree < 1 or degree > T:
        return None
    positions = _locator_roots(locator, degree)
    if len(positions) != degree or any(position >= SHORT_N for position in positions):
        return None

    corrected = received
    for position in positions:
        corrected ^= 1 << position
    if any(_syndromes(corrected)):
        return None

    message = corrected >> PARITY_BITS
    if message >= (1 << SHORT_K):
        return None
    return message, corrected, len(positions)
