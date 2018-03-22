# -*- encoding: utf-8 -*-
#
# This IDA script decrypts the strings inside *unpacked* samples of
# Glupteba.AY samples For details about Glupteba.AY, see:
# https://www.welivesecurity.com/2018/03/22/glupteba-no-longer-windigo/
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Author:
# Frédéric Vachon <frederic.vachon@eset.com>
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
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import struct

import idautils
import ida_idp
import ida_search

import mersenne


def find_crypt_info():
    info = {
        'addr': [],
        'xor_key': ''
    }
    # Find the decryption routines
    addr = 0
    while True:
        # Search for magic value in the decryption functions
        addr, _ = ida_search.find_imm(addr + 1, SEARCH_DOWN, 0x3C6EF35F)
        if addr == 0xffffffff:
            break
        info['addr'].append(ida_funcs.get_func(addr).startEA)
        inst_addr = addr

    # Find xor key
    info['xor_key'] = find_xor_key(inst_addr)
    return info


def find_xor_key(magic_byte_addr):
    xor_key = ''
    i = 0
    curr_addr = magic_byte_addr
    while xor_key == '' and i < 20:
        inst, _ = idautils.DecodePrecedingInstruction(curr_addr)
        if inst.get_canon_mnem() == 'mov' and inst.Op1.type == o_displ:
            if inst.Op2.type == o_imm:
                xor_key = ida_bytes.get_bytes(inst.Op2.value, 0x10)
        curr_addr = inst.ea
        i += 1
    return xor_key


def decrypt_strings(info):
    xor_key = info['xor_key']
    for i, crypt_func_addr in enumerate(info['addr']):
        for xref in idautils.XrefsTo(crypt_func_addr):
            str_addr, str_len = find_params(xref)
            if str_addr == 0 or str_len == 0:
                print "ERROR: Can't find parameters for func" \
                  "at 0x{:08X}".format(xref)

            cipher = ida_bytes.get_bytes(str_addr, str_len)
            s = decrypt_str(cipher, xor_key)
            # Strings from the first decryption routine are UTF-16 encoded
            if i == 0:
                s = s.decode('utf-16').encode('utf-8')
                print "Str at 0x{:08X}: u'{}'".format(xref.frm, s)
                ida_bytes.set_cmt(xref.frm, "u'{}'".format(s), False)
                f_addr = ida_funcs.get_func(xref.frm)
                for xref_ in idautils.XrefsTo(f_addr.startEA):
                    ida_bytes.set_cmt(xref_.frm, "u'{}'".format(s), False)
            else:
                print "Str at 0x{:08X} : {}".format(xref.frm, repr(s))
                ida_bytes.set_cmt(xref.frm, repr(s), False)
                f_addr = ida_funcs.get_func(xref.frm)
                for xref_ in idautils.XrefsTo(f_addr.startEA):
                    ida_bytes.set_cmt(xref_.frm, repr(s), False)


def find_params(xref):
    str_len = 0
    str_addr = 0
    curr_addr = xref.frm
    i = 0
    while (str_len == 0 or str_addr == 0) and i < 10:
        inst, _ = idautils.DecodePrecedingInstruction(curr_addr)
        if inst.get_canon_mnem() == 'mov' and inst.Op1.type == o_reg and \
           inst.Op1.reg == ida_idp.str2reg('edx') and inst.Op2.type == o_imm:
            str_addr = inst.Op2.value
        elif inst.get_canon_mnem() == 'push':
            str_len = inst.Op1.value
        i += 1

        curr_addr = inst.ea
    return str_addr, str_len


def decrypt_str(cipher, key):
    trunc_key = struct.unpack('<I', key[:4])[0]
    mersenne.initialize_generator(trunc_key)

    out = []
    for b in cipher:
        rand_no = mersenne.extract_number() % 0x100
        out.append(ord(b) ^ rand_no)

    for i, b in enumerate(out):
        out[i] ^= ord(key[i % 0x10])

    bl = 0x62
    for i, b in enumerate(out):
        bl ^= (b - (i % 0x100))
        bl ^= 0x67
        out[i] = bl & 0xff

    return ''.join(map(chr, out))


info = find_crypt_info()

if len(info.get('addr')) == 0:
    print "ERROR: Can't find decryption routines"
elif info.get('xor_key') == '':
    print "ERROR: Can't find the decryption key"
else:
    decrypt_strings(info)
