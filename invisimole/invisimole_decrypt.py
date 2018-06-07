#!/usr/bin/env python
#
# Code related to ESET's InvisiMole research.
# This script can decrypt the RC2CL and RC2FM modules from the InvisiMole DLL wrapper.
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
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

import os
import sys
import struct
import pefile

def decrypt_payload(data, size):

    result = bytearray()

    add_value = 0xAD3A019E
    for i in range(size//4 - 1):

        dword = struct.unpack_from('<L', data, i * 4)[0]
        xor_key = ((0xA9 * i * 4) + add_value) & 0xFFFFFFFF
        add_value = dword
        dword = (dword ^ xor_key) & 0xFFFFFFFF

        result += struct.pack('<L', dword)

    result += struct.pack('<L', 0)
    return result
    
def save_payload(filename, payload_name, payload_data, payload_size):

    decrypted_data = decrypt_payload(payload_data, payload_size)

    f = open('{0:s}_{1:s}.bin'.format(os.path.splitext(filename)[0], payload_name), 'wb')
    f.write(decrypted_data)
    f.close()

    fixed_decrypted_data = bytearray([0x4D, 0x5A, 0x90, 0x00]) + decrypted_data[4:]

    f = open('{0:s}_{1:s}_fixed.bin'.format(os.path.splitext(filename)[0], payload_name), 'wb')
    f.write(fixed_decrypted_data)
    f.close()            
    return

def main():

    if len(sys.argv) < 2:
        print('Usage: {0:s} input_dll'.format(sys.argv[0]))
        return

    filename = sys.argv[1]
    pe = pefile.PE(filename)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    
    RC2CL_offset, RC2CL_size = 0, 0
    RC2FM_offset, RC2FM_size = 0, 0

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:

            if pefile.RESOURCE_TYPE.get(resource_type.struct.Id, '-') == 'RT_RCDATA':

                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:

                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:

                                if hasattr(resource_lang, 'data'):

                                    if str(resource_id.name) == 'RC2CL':
                                        RC2CL_offset = resource_lang.data.struct.OffsetToData
                                        RC2CL_size = resource_lang.data.struct.Size
                                    elif str(resource_id.name) == 'RC2FM':
                                        RC2FM_offset = resource_lang.data.struct.OffsetToData
                                        RC2FM_size = resource_lang.data.struct.Size

    if RC2CL_offset != 0 and RC2CL_size != 0:
        print('RC2CL resource {0:08X} - {1:08X}'.format(RC2CL_offset, RC2CL_size))

        save_payload(filename, 'RC2CL', pe.get_data(RC2CL_offset, RC2CL_size), RC2CL_size)
    else:
        print('RC2CL resource not found')

    if RC2FM_offset != 0 and RC2FM_size != 0:
        print('RC2FM resource {0:08X} - {1:08X}'.format(RC2FM_offset, RC2FM_size))

        save_payload(filename, 'RC2FM', pe.get_data(RC2FM_offset, RC2FM_size), RC2FM_size)
    else:
        print('RC2FM resource not found')

if __name__ == "__main__":
    main()
