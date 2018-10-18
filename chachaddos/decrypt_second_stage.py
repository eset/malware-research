#!/usr/bin/env python
#
# This script decrypt the 2nd stage of Linux/ChachaDDoS by emulating the
# decryption function (ChaCha) in first stage samples.
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Author: Hugo Porcher <hugo.porcher@eset.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2018 ESET
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

from miasm2.analysis.sandbox import Sandbox_Linux_x86_64
from miasm2.analysis.binary import Container
from miasm2.os_dep.linux_stdlib import linobjs
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE

parser = Sandbox_Linux_x86_64.parser(description="2nd stage decryptor")
parser.add_argument("in_filename", help="2nd stage encrypted filename (in)")
parser.add_argument("out_filename", help="2nd stage decrypted filename (out)")
options = parser.parse_args()

# First stage sample name (also its SHA-1)
first_stage_fn = "0413f832d8161187172aef7a769586515f969479"
# ChaCha decryption function address for this particular sample
decrypt_func_addr = 0x400830
# Memory address of the initialization vector
iv_addr = 0x614000
# Memory address of the key
key_addr = 0x614020
# Arbitrary memory address to map the encrypted file in memory
in_addr = 0x40000000

# Create new instance of x86_64 sandbox to emulate the decryption function
sb = Sandbox_Linux_x86_64(first_stage_fn, options, globals())
with open(first_stage_fn, "rb") as first_stage, open(options.in_filename) as enc_bin:
    cont = Container.from_stream(first_stage)
    in_data = enc_bin.read()
    in_size = len(in_data)

# Allocate memory to store the output
out_addr = linobjs.heap.alloc(sb.jitter, in_size)
# Map the encrypted file in memory
sb.jitter.vm.add_memory_page(in_addr, PAGE_READ | PAGE_WRITE, in_data)

# Call the decryption function with the good arguments
sb.call(decrypt_func_addr, key_addr, 1, iv_addr, in_addr, out_addr, in_size)

# Get the decrypted data from memory
out_bin = sb.jitter.vm.get_mem(out_addr, in_size)
with open(options.out_filename, "wb") as dec_bin:
    dec_bin.write(out_bin)
