# This file is a IDA Python script for naming FinFisher VM handlers. For more
# details about FinFisher deobfuscation see "ESET's guide to deobfuscating and
# devirtualizing FinFisher" at
# https://www.welivesecurity.com/wp-content/uploads/2018/01/WP-FinFisher.pdf
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Author:
# Filip Kafka <filip.kafka@eset.sk>
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

import sys
from idc import Dword, Byte, MakeName
from idautils import DecodeInstruction

SIGS = {
    '8d4b408b432c8b0a90800f95c2a980000f95c03ac275ff631c' : 'case_0_JL_loc1',
    '8d4b408b432c8b0a9400074ff631c' : 'case_1_JNP_loc1',
    '8d4b408b432c8b0a94000075a90800f95c2a980000f95c03ac275ff631c' : 'case_2_JLE_loc1',
    '8d4b408b7b508b432c83e02f8dbc38311812b5c787cfe7ed4ae92f8b066c787d3e7ed4af9b8e80000588d80' : 'case_3_vm_jcc',
    '8b7b508b432c83e02f3f85766c77ac6668137316783c728d7340fb64b3df3a4c67e98037818b43c89471c64756c80775af83318588b632c' : 'case_4_exec_native_code',
    '8d4b408b98b438898833188b43c8b632c' : 'case_5_mov_tmp_REGref_arg0',
    '8b7b508b432c83e02f3f85766c77ac6668137316783c728d7340fb64b3df3a4c67e98037818b43c89471c64756c80775af83318588b632c' : 'case_6_exec_native_code',
    '8d4b408b432c8b0a94000075ff631c' : 'case_7_JZ_loc1',
    '8d4b408b432c8b0a94000075a90800f95c2a980000f95c03ac275ff6318' : 'case_8_JG_loc1',
    '8d43408b089438833188b43c8b632c' : 'case_9_mov_tmp_REG_arg0',
    '33c9894b8833188b632c8b43c' : 'case_A_zero_tmp_REG',
    '8d4b408b432c8b0a98000075ff631c' : 'case_B_JS_loc1',
    '8d4b40fb69b870002bc18b4b2c8b548148b4b88911833188b43c8b632c' : 'case_C_mov_tmp_REGDeref_tmp_REG',
    '8d4b40fb69b870002bc18b4b2c8b4481489438833188b43c8b632c' : 'case_D_mov_tmp_REG_tmp_REG',
    '8d4b408b432c8b0a9100075ff631c' : 'case_E_JB_loc1',
    '8d4b408b432c8b0a9100075a94000075ff631c' : 'case_F_JBE_loc1',
    '8d4b408b432c8b0a94000074ff631c' : 'case_10_JNZ_loc1',
    '8d4b408b432c8b0a9080074ff631c' : 'case_11_JNO_loc1',
    '8b7b50834350308d4b408b414343285766c773f50668137a231c6472c280772aa8d57d83c73891783ef3c7477a300080777cb83c7889783ef8c647cf28077c3183c7dc67688b383c0188947183c7566c7777fe668137176283c72c672d803745895f183c75c67848037df478b4314c67408037288947183c75c67928037515f8b632c' : 'case_12_vm_call',
    '8d4b40b870002b18b532c8b4482489438833188b43c8b632c' : 'case_13_mov_tmp_REG_tmp_REG_notRly',
    '8d4b408b432c8b0a9400075ff631c' : 'case_14_JP_loc1',
    '8d4b40fb69b870002bc18b4b2c8b5388954814833188b43c8b632c' : 'case_15_mov_tmp_REG_tmp_REG',
    '8d4b408b432c8b0a9080075ff631c' : 'case_16_JO_loc1',
    '8d4b408b432c8b0a90800f95c2a980000f95c03ac274ff631c' : 'case_17_JGE_loc1',
    '8b4388b089438833188b43c8b632c' : 'case_18_deref_tmp_REG',
    '8d4b408b4388b9d3e089438833188b43c8b632c' : 'case_19_shl_tmp_REG_arg0l',
    '8d4b408b432c8b0a98000074ff631c' : 'case_1A_JNS_loc1',
    '8d4b408b432c8b0a9100074ff631c' : 'case_1B_JNB_loc1',
    '8b7b2c8b732c83ef4b924000fcf3a4836b2c48b4b2c8b438894124833188b43c8b632c' : 'case_1C_push_tmp_REG',
    '8d4b408b432c8b0a94000075a9100075ff6318' : 'case_1D_JA_loc1',
    '8d4b40b870002b18b532c8b448241438833188b43c8b632c' : 'case_1E_add_stack_val_to_tmp_REG',
    '8b7b508343503066c77ac3766813731565783c728d4b40c672e803746fb6433d3c783c058947183c758d714fb64b3df3a45ac671280377a8b383c0188947183c7566c777f306681371fac83c72c671f803777895f183c75c677080372b47c6798037618b4b14894f183c75c67778037b48b632c8d12' : 'case_1F_vm_jmp',
    '8d4b408b914b8833188b43c8b632c' : 'case_20_add_arg0_to_tmp_REG',
    '8d4b408b98b438891833188b632c8b43c' : 'case_21_mov_tmp_REG_to_arg0Dereferenced'
}

SWITCH = 0 # addr of jmp     dword ptr [eax+ecx*4] (jump to vm_handlers)
SWITCH_SIZE = 34

def append_bytes(instr, addr):
    for j in range(instr.size):
        sig.append(Byte(addr))
        addr += 1
    return addr

def makeSigName(sig_name, vm_handler):
    print "naming %x as %s" % (vm_handler, sig_name)
    MakeName(vm_handler, sig_name)
    return

if SWITCH == 0:
    print "First specify address of switch jump - jump to vm_handlers!"
    sys.exit(1)

for i in range(SWITCH_SIZE):
    addr = Dword(SWITCH+i*4)
    faddr = addr

    sig = []

    while 1:
        instr = DecodeInstruction(addr)
        if instr.get_canon_mnem() == "jmp" and (Byte(addr) == 0xeb or Byte(addr) == 0xe9):
            addr = instr.Op1.addr
            continue
        if instr.get_canon_mnem() == "jmp" and Byte(addr) == 0xff and Byte(addr+1) == 0x63 and (Byte(addr+2) == 0x18 or Byte(addr+2) == 0x1C):
            addr = append_bytes(instr, addr)
            break
        if instr.get_canon_mnem() == "jmp" and Byte(addr) == 0xff:
            break
        if instr.get_canon_mnem() == "jz":
            sig.append(Byte(addr))
            addr += instr.size
            continue
        if instr.get_canon_mnem() == "jnz":
            sig.append(Byte(addr))
            addr += instr.size
            continue
        if instr.get_canon_mnem() == "nop":
            addr += 1
            continue
        addr = append_bytes(instr, addr)

    sig_str = "".join([hex(l)[2:] for l in sig])
    hsig = ''.join(map(chr, sig)).encode("hex")

    for key, value in SIGS.iteritems():
        if len(key) > len(sig_str):
            if key.find(sig_str) >= 0:
                makeSigName(value, faddr)
        else:
            if sig_str.find(key) >= 0:
                makeSigName(value, faddr)
