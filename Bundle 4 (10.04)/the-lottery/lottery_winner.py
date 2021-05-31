import sys
import math
import struct
import random
import requests
from z3 import *
from decimal import *
import re

# Most code from https://github.com/d0nutptr/v8_rand_buster/blob/master/xs128p.py & https://gist.github.com/FadedCoder/b7f23039e8933bcc07d0dc61da093b29
# I used the main function from FadedCoder's Hax

# This script exploits the PSEUDO-randomness of the math.random() function &
# predicts the next number sequence from the output of the lottery losing messages / previous numbers.
# The prize/flag is outputed after sending the generated number sequence to the lottery.
# Due to the cache of math.random() / XorShift128+ only having  64 "random" values,
# the script might fail when the some of the lottery numbers are based on a different Cache Fill Event.
# Restarting the script will fix the "issue".

# Variables
MASK = 0xFFFFFFFFFFFFFFFF


# xor_shift_128_plus algorithm
def xs128p(state0, state1, browser):
    s1 = state0 & MASK
    s0 = state1 & MASK
    s1 ^= (s1 << 23) & MASK
    s1 ^= (s1 >> 17) & MASK
    s1 ^= s0 & MASK
    s1 ^= (s0 >> 26) & MASK
    state0 = state1 & MASK
    state1 = s1 & MASK
    generated = state0 & MASK

    return state0, state1, generated


def reverse17(val):
    return val ^ (val >> 17) ^ (val >> 34) ^ (val >> 51)


def reverse23(val):
    return (val ^ (val << 23) ^ (val << 46)) & MASK


def xs128p_backward(state0, state1):
    prev_state1 = state0
    prev_state0 = state1 ^ (state0 >> 26)
    prev_state0 = prev_state0 ^ state0
    prev_state0 = reverse17(prev_state0)
    prev_state0 = reverse23(prev_state0)
    generated = prev_state0
    return prev_state0, prev_state1, generated


# Chrome/NodeJS nextDouble():
    # (state0 | 0x3FF0000000000000) - 1.0


def sym_xs128p(sym_state0, sym_state1):
    # Symbolically represent xs128p
    s1 = sym_state0
    s0 = sym_state1
    s1 ^= (s1 << 23)
    s1 ^= LShR(s1, 17)
    s1 ^= s0
    s1 ^= LShR(s0, 26)
    sym_state0 = sym_state1
    sym_state1 = s1
    # end symbolic execution
    return sym_state0, sym_state1


# Symbolic execution of xs128p
def sym_floor_random(slvr, sym_state0, sym_state1, generated, multiple):
    sym_state0, sym_state1 = sym_xs128p(sym_state0, sym_state1)

    # "::ToDouble"
    calc = LShR(sym_state0, 12)

    """
    Symbolically compatible Math.floor expression.
 
    Here's how it works:
 
    64-bit floating point numbers are represented using IEEE 754 (https://en.wikipedia.org/wiki/Double-precision_floating-point_format) which describes how
    bit vectors represent decimal values. In our specific case, we're dealing with a function (Math.random) that only generates numbers in the range [0, 1).
 
    This allows us to make some assumptions in how we deal with floating point numbers (like ignoring parts of the bitvector entirely).
 
    The 64bit floating point is laid out as follows
    [1 bit sign][11 bit expr][52 bit "mantissa"]
 
    The formula to calculate the value is as follows: (-1)^sign * (1 + Sigma_{i=1 -> 52}(M_{52 - i} * 2^-i)) * 2^(expr - 1023)
 
    Therefore 0_01111111111_1100000000000000000000000000000000000000000000000000 is equal to "1.75"
 
    sign => 0 => ((-1) ^ 0) => 1
    expr => 1023 => 2^(expr - 1023) => 1
    mantissa => <bitstring> => (1 + sum(M_{52 - i} * 2^-i) => 1.75
 
    1 * 1 * 1.75 = 1.75 :)
 
    Clearly we can ignore the sign as our numbers are entirely non-negative.
 
    Additionally, we know that our values are between 0 and 1 (exclusive) and therefore the expr MUST be, at most, 1023, always.
 
    What about the expr?
 
    """

    lower = from_double(Decimal(generated) / Decimal(multiple))
    upper = from_double((Decimal(generated) + 1) / Decimal(multiple))

    lower_mantissa = (lower & 0x000FFFFFFFFFFFFF)
    upper_mantissa = (upper & 0x000FFFFFFFFFFFFF)
    upper_expr = (upper >> 52) & 0x7FF

    slvr.add(And(lower_mantissa <= calc, Or(
        upper_mantissa >= calc, upper_expr == 1024)))
    return sym_state0, sym_state1


def to_double(out):
    double_bits = (out >> 12) | 0x3FF0000000000000
    double = struct.unpack('d', struct.pack('<Q', double_bits))[0] - 1
    return double


def from_double(dbl):
    """
    https://github.com/v8/v8/blob/master/src/base/utils/random-number-generator.h#L111
    This function acts as the inverse to @to_double. The main difference is that we
    use 0x7fffffffffffffff as our mask as this ensures the result _must_ be not-negative
    but makes no other assumptions about the underlying value.
    That being said, it should be safe to change the flag to 0x3ff...
    """
    return struct.unpack('<Q', struct.pack('d', dbl + 1))[0] & 0x7FFFFFFFFFFFFFFF


def getVals(url):
    msg = requests.post(url,
                        json={"guess": [69, 69, 69, 4, 2, 0]}).text
    arr_str = re.findall(r"\[.*]", msg)[0]
    return eval(arr_str)


def sendResult(win_nums, url):
    msg = requests.post(url,
                        json={"guess": win_nums}).text
    print("--" * 30)
    print(msg)
    print("--" * 30)


def main():
    url_id = input("URL id: ")
    url = "https://" + url_id + ".idocker.vuln.land/make_guess"

    # Enter at least the 18 (3x6 values) first random numbers you observed here:
    a = []

    for i in range(3):
        arr = getVals(url)
        a = a + arr

    known_vals = a

    # Invert List because math.random() inverts its randomly generated values in the cache
    known_vals = known_vals[::-1]

    # setup symbolic state for xorshift128+
    ostate0, ostate1 = BitVecs('ostate0 ostate1', 64)
    sym_state0 = ostate0
    sym_state1 = ostate1
    slvr = Solver()
    conditions = []

    # run symbolic xorshift128+ algorithm for the length of the values given
    # using the recovered numbers as constraints
    for ea in range(len(known_vals)):
        sym_state0, sym_state1 = sym_floor_random(
            slvr, sym_state0, sym_state1, known_vals[ea], multiple=10000)

    if slvr.check() == sat:
        # get a solved state
        m = slvr.model()
        state0 = m[ostate0].as_long()
        state1 = m[ostate1].as_long()
        slvr.add(Or(ostate0 != m[ostate0], ostate1 != m[ostate1]))
        if slvr.check() == sat:
            print('WARNING: multiple solutions found! Sse more Values!')
        #print('State:', state0, state1)
        #print("--" * 30)
        generated = [to_double(state0 & MASK)]

        # generate random numbers from recovered state
        for idx in range(15):
            state0, state1, out = xs128p_backward(state0, state1)
            out = state0 & MASK

            double = to_double(out)
            generated.append(double)

        generated = [math.floor(k*10000) for k in generated]
        print("Next winning numbers: " + str(generated[:6]))
        sendResult(generated[:6], url)
    else:
        print('Cant find a solution...')


main()
