# -*- encoding: utf-8 -*-
#
# This IDA script decrypts the strings inside *unpacked* samples of the
# Win32/TorrentLocker crypto-ransomware.
# For details about TorrentLocker, see:
# http://www.welivesecurity.com/2016/09/01/torrentlocker-crypto-ransomware-still-active-using-tactics/
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Authors:
# Frédéric Vachon <frederic.vachon@eset.com>
# Marc-Etienne M.Léveillé <leveille@eset.com>
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2016 ESET
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

import idaapi
import idautils
import idc
import struct

for func_addr in idautils.Functions(0, 0xffffffff):
    # Signature is based on the beginning of the decryption function:
    # 53                  push    ebx
    # 8B DA               mov     ebx, edx
    # 56                  push    esi
    # 33 F6               xor     esi, esi
    # 57                  push    edi
    # 8B F9               mov     edi, ecx
    # 39 34 DD C4 DE 06+  cmp     dword_1006DEC4[ebx*8], esi
    if idaapi.get_many_bytes(func_addr, 12) == "538BDA5633F6578BF93934DD".decode('hex'):
        decoding_func = idaapi.get_func(func_addr)
        break

for addr in idautils.Heads(decoding_func.startEA, decoding_func.endEA):
    if chr(idaapi.get_byte(addr)) == "\x8A":
        # 8A 89 B0 D5 04 10  mov     cl, key[ecx]
        #       ^ key offset
        key_offset = struct.unpack("<I", idaapi.get_many_bytes(addr + 2, 4))[0]
    elif idaapi.get_many_bytes(addr, 1) == "\x6B":
        # 6B C2 33                   imul    eax, edx, 51
        #       ^ key length
        key_len = idaapi.get_byte(addr + 2)
    elif idaapi.get_many_bytes(addr, 3) == "\x8B\x04\xDD":
        # 8B 04 DD C0 DE 06 10       mov     eax, packed_strings_list[ebx*8]
        #          ^ address of string list
        struct_base = struct.unpack("<I", idaapi.get_many_bytes(addr + 3, 4))[0]

print "[*] Decoding function : 0x{:08x}".format(int(decoding_func.startEA))
print "[*] Encoded string list base : 0x{:08x}".format(struct_base)

data_seg = idaapi.get_segm_by_name(".data")
xor_key = idaapi.get_many_bytes(key_offset, key_len)
index = 0

while True:
    addr = struct_base + index * 8
    data_ptr, size = struct.unpack("<II", idaapi.get_many_bytes(addr, 8))

    if data_ptr < data_seg.startEA or data_ptr > data_seg.endEA:
        # We don't know how many strings there are so we stop when the pointer
        # to the data doesn't make sense.
        break

    data = idaapi.get_many_bytes(data_ptr, size)
    decrypted_string = "".join(
        [chr(ord(data[i]) ^ ord(xor_key[i % len(xor_key)])) for i in range(size)]
    )

    print "{:03d} : '{:s}'".format(index, decrypted_string)
    idc.MakeComm(addr, "{:03d} : {:s}".format(index, repr(decrypted_string)))

    index += 1
