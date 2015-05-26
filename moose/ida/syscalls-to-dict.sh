#!/bin/bash
#
# Code related to ESET's Linux/Moose research
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# This code is provided to the community under the two-clause BSD license as
# follows:
#
# Copyright (C) 2015 ESET
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
#
echo "#!/usr/bin/env python" > mips_syscalls.py
echo "" >> mips_syscalls.py 
echo "__NR_Linux = 4000" >> mips_syscalls.py
echo "syscall_table = dict()" >> mips_syscalls.py

# head: interested in only the mips o32 syscalls (beginning of file)
# grep: keeping good lines
# awk: search / replace building a python dict
head -380 unistd.h | egrep "^#define __NR.*\(__NR_Linux \+" \
	| awk '{ print "syscall_table["$3$4$5"] = \""$2"\""}' >> mips_syscalls.py
