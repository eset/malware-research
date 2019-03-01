# This script emulates the shellcode used in OceanLotus latest campaign
# using the side-loading technique against legitimate "rastls.exe" application
# from Symantec
# Details about OceanLotus can be found at 
# https://www.welivesecurity.com/wp-content/uploads/2018/03/ESET_OceanLotus.pdf
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
# Romain Dumont <romain.dumont@eset.com>
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
#encoding: utf-8

import os
from struct import pack, unpack
from miasm2.analysis.sandbox import Sandbox_Win_x86_32
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.os_dep.win_api_x86_32 import *

reservedRegion=[]

# Avoid zeroing-out memory
def kernel32_RtlZeroMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(["Destination", "Length"])
    jitter.func_ret_stdcall(ret_ad, 0)
    
# Break when the shellcode tries to resolve API addresses    
def kernel32_LoadLibrary(jitter,get_str):
    jitter.run = False
    print hex(jitter.pc)
    return False
    
# The modification done is because the emulated version of VirtualAlloc
# does not implement the support of alloctype 
# Here, the first call to VirtualAlloc reserves a region and all the
# subsequent calls commit the pages
# The hack here is to comment the first call to VirtualAlloc
def kernel32_VirtualAlloc(jitter):
    global reservedRegion
    ret_ad, args = jitter.func_args_stdcall(['lpvoid', 'dwsize',
                                             'alloc_type', 'flprotect'])

    if not args.flprotect in ACCESS_DICT:
        raise ValueError('unknown access dw!')

    if args.lpvoid == 0:
        alloc_addr = winobjs.heap.next_addr(args.dwsize)
        jitter.vm.add_memory_page(
            alloc_addr, ACCESS_DICT[args.flprotect], "\x00" * args.dwsize,
            "Alloc in %s ret 0x%X" % (whoami(), ret_ad))
    else:
        all_mem = jitter.vm.get_all_memory()
        if args.lpvoid in all_mem:
            alloc_addr = args.lpvoid
            jitter.vm.set_mem_access(args.lpvoid, ACCESS_DICT[args.flprotect])
        else:
            #alloc_addr = winobjs.heap.next_addr(args.dwsize)
            alloc_addr = args.lpvoid
            #jitter.vm.add_memory_page(
                #alloc_addr, ACCESS_DICT[args.flprotect], "\x00" * args.dwsize,
                #"Alloc in %s ret 0x%X" % (whoami(), ret_ad))
    if args.alloc_type == 0x2000:
        reservedRegion+=[alloc_addr,args.dwsize]
    log.info('VirtualAlloc addr: 0x%x', alloc_addr)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)
    
    
# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
parser.add_argument("shellcode", help="shellcode file")
parser.add_argument("outputFile", help="output file")
options = parser.parse_args()

# Create sandbox
sb = Sandbox_Win_x86_32(options.filename, options, globals())

# Read and map the shellcode
with open(options.shellcode) as f:
    data = f.read()
run_addr = 0x40000000
sb.jitter.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

# Run the shellcode
sb.jitter.init_run(run_addr)
sb.jitter.continue_run()
regionStart, regionSize = reservedRegion
binary = sb.jitter.vm.get_mem(regionStart,regionSize)
binList = [ c for c in binary ]

# Parse the PE to get the SectionHeaders fields
NT = unpack("<I",binary[0x3c:0x3c+4])[0]
NumberOfSections = unpack("<H",binary[NT+6:NT+6+2])[0]
SectionHeaders = NT + unpack("<H",binary[NT+0x14:NT+0x14+2])[0] + 0x18
i=0
#first dump until .text Raw Address
binary="".join(str(x) for x in binList[:unpack("<I","".join(binList[SectionHeaders+0x14:SectionHeaders+0x14+4]))[0]])
# FIX directories: fix RawAddress fields
while i < NumberOfSections:
    VirtAddress=unpack("<I","".join(binList[SectionHeaders+0xc+(i*0x28):SectionHeaders+0xc+(i*0x28)+4]))[0]
    RawSize=unpack("<I","".join(binList[SectionHeaders+0x10+(i*0x28):SectionHeaders+0x10+(i*0x28)+4]))[0]
    binary+= "".join(str(x) for x in binList[VirtAddress:VirtAddress+RawSize])
    i += 1
with open(options.outputFile, "wb") as f:
    f.write(binary)
