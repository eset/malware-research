# -*- encoding: utf-8 -*-
#
# Copyright 2012 Yaşar Arabacı
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""
Based on the pseudocode in
https://en.wikipedia.org/wiki/Mersenne_Twister. Generates uniformly
distributed 32-bit integers in the range [0, 232 − 1] with the MT19937
algorithm

Author : Yaşar Arabacı <yasar11732@gmail.com>
Modified by : Frédéric Vachon <frederic.vachon@eset.com>
"""

# Create a length 624 list to store the state of the generator
MT = [0 for i in xrange(624)]
index = 0

# To get last 32 bits
bitmask_1 = (2 ** 32) - 1

# To get 32. bit
bitmask_2 = 2 ** 31

# To get last 31 bits
bitmask_3 = (2 ** 31) - 1


def generate_numbers():
    "Generate an array of 624 untempered numbers"
    global MT
    for i in xrange(624):
        y = (MT[i] & bitmask_2) + (MT[(i + 1) % 624] & bitmask_3)
        MT[i] = MT[(i + 397) % 624] ^ ((y >> 1) & (~(-1 << 31) & 0xffffffff))
        if y % 2 != 0:
            MT[i] ^= 0x9908b0df


def initialize_generator(seed):
    "Initialize the generator from a seed"
    global MT
    global index
    global bitmask_1
    MT = [0 for i in xrange(624)]
    index = 0
    MT[0] = seed
    for i in xrange(1, 624):
        MT[i] = 0x6c078965 * ((MT[i-1]) ^ ((MT[i-1] >> 30) & 0x3)) + i


def extract_number():
    """
    Extract a tempered pseudorandom number based on the index-th value,
    calling generate_numbers() every 624 numbers
    """
    global index
    global MT
    if index == 0:
        generate_numbers()
    y = MT[index]
    y ^= y >> 11 & (~(-1 << 21) & 0xffffffff)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18 & (~(-1 << 14) & 0xffffffff)

    index = (index + 1) % 624
    return y


if __name__ == "__main__":
    expected = [0xc3, 0x3f, 0xd3, 0x94, 0x50, 0x52]
    initialize_generator(0x56C9E04F)
    for i in xrange(len(expected)):
        print "(result, expected) : (0x{:02X}, 0x{:02X})".format(
            extract_number() % 0x100, expected[i]
        )
