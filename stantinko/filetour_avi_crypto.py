#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Code related to ESET's Stantinko research.
# This script decrypts the encrypted executables downloaded by FileTour as .avi.
# The encrypted file should be written in stdin, the decrypted executable will
# be written in stdout. 
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
# Marc-Etienne M.Léveillé <leveille@eset.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2017 ESET
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys

HS_NIBBLE_K1=[ int(x, 16) for x in "C9AF0DE34127856B" ]
HS_NIBBLE_K2=[ int(x, 16) for x in "AB01EF45238967CD" ]

b = sys.stdin.read(1)
while len(b) == 1:
    d = ord(b)
    d ^= 0x0E
    if (d & 0xF) in (0xE, 0xF):
        d = (HS_NIBBLE_K2.index(d >> 4) << 4) | (d & 0xF)
    else:
        d = (HS_NIBBLE_K1.index(d >> 4) << 4) | (d & 0xF)
    sys.stdout.write(chr(d))
    b = sys.stdin.read(1)
