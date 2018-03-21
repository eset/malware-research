# This script extracts the backdoor components of latest OceanLotus
# campaign using the side-loading technique against legitimate "rastls.exe" 
# application from Symantec
# The extracted elements are "rastls.exe", "rastls.dll" and "OUTLFLTR.dat".
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

import sys
import lief
import pylzma
from Crypto.Cipher import AES
from struct import unpack
from pkg_resources import parse_version
from kaitaistruct import __version__ as ks_version, KaitaiStruct, KaitaiStream, BytesIO


if parse_version(ks_version) < parse_version('0.7'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.7 or later is required, but you have %s" % (ks_version))

class OlDropperStruct(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.total_length = self._io.read_u4le()
        self.install_paths_length = self._io.read_u4le()
        self._raw_install_paths = self._io.read_bytes(self.install_paths_length)
        io = KaitaiStream(BytesIO(self._raw_install_paths))
        self.install_paths = self._root.InstallPathsStruct(io, self, self._root)
        self.binaries_length = self._io.read_u4le()
        self._raw_binaries = self._io.read_bytes(self.binaries_length)
        io = KaitaiStream(BytesIO(self._raw_binaries))
        self.binaries = self._root.BinariesStruct(io, self, self._root)
        self.persistence_length = self._io.read_u4le()
        self._raw_persistence_strings = self._io.read_bytes(self.persistence_length)
        io = KaitaiStream(BytesIO(self._raw_persistence_strings))
        self.persistence_strings = self._root.PersistenceStruct(io, self, self._root)

    class PathsStruct(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.paths = []
            i = 0
            while not self._io.is_eof():
                self.paths.append(self._root.Utf16Str(self._io, self, self._root))
                i += 1



    class BinaryStruct(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.binary_length = self._io.read_u4le()
            self.data = self._io.read_bytes(self.binary_length)


    class InstallPathsStruct(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.appdata_path_length = self._io.read_u4le()
            self._raw_appdata_paths = self._io.read_bytes(self.appdata_path_length)
            io = KaitaiStream(BytesIO(self._raw_appdata_paths))
            self.appdata_paths = self._root.PathsStruct(io, self, self._root)
            self.progfile_path_length = self._io.read_u4le()
            self._raw_progfile_paths = self._io.read_bytes(self.progfile_path_length)
            io = KaitaiStream(BytesIO(self._raw_progfile_paths))
            self.progfile_paths = self._root.PathsStruct(io, self, self._root)


    class PersistenceStruct(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.registry_persistence_length = self._io.read_u4le()
            self.regkey_str = self._root.Utf16Str(self._io, self, self._root)
            self.regvalue_str = self._root.Utf16Str(self._io, self, self._root)
            self.service_persistence_length = self._io.read_u4le()
            self.servicename_str = self._root.Utf16Str(self._io, self, self._root)
            self.displayname_str = self._root.Utf16Str(self._io, self, self._root)


    class Utf16Str(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.str_len = self._io.read_u4le()
            self.str_buf = (self._io.read_bytes(self.str_len)).decode(u"UTF-16LE")


    class BinariesStruct(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.binary = []
            i = 0
            while not self._io.is_eof():
                self.binary.append(self._root.BinaryStruct(self._io, self, self._root))
                i += 1

def dropFile(name,data):
    print "Extracting: ",name
    with open(name,"wb") as f:
        f.write(data)

if len(sys.argv) != 2:
    print "Usage: script [binary]"
    exit(-1)

b = lief.parse(sys.argv[1])
key = ''.join([ chr(c) for c in b.get_section(".data").content[:0x20] ])
iv  = ''.join([ chr(c) for c in b.get_section(".data").content[0x20:0x30] ])

root = b.resources
rcdata = None
for i in root.childs:
    if i.id == 0xa:
        rcdata=i
        break
rsrc = ''.join([ chr(c) for c in rcdata.childs[0].childs[0].content ])

a = AES.new(key, AES.MODE_CBC, iv)
compressedShellcode = a.decrypt(rsrc)
size = unpack("<I",compressedShellcode[4:8])[0]
files = pylzma.decompress(compressedShellcode[8:], maxlength=size)

file_struct = OlDropperStruct.from_bytes(files)
print "\nInstall paths:"
print "\t- ",file_struct.install_paths.appdata_paths.paths[0].str_buf.rsplit('\\',1)[0]
print "\t- ",file_struct.install_paths.progfile_paths.paths[0].str_buf.rsplit('\\',1)[0]

print "\nPersistence mechanisms:"
print "\t- Registry key: ",file_struct.persistence_strings.regkey_str.str_buf
print "\t- Registry value: ",file_struct.persistence_strings.regvalue_str.str_buf[:-1]
print "\n\t- Servicename: ",file_struct.persistence_strings.servicename_str.str_buf[:-1]
print "\t- Service displayname: ",file_struct.persistence_strings.displayname_str.str_buf[:-1],"\n"

for i,file in enumerate(file_struct.install_paths.appdata_paths.paths):
    dropFile(file.str_buf.rsplit('\\',1)[1],file_struct.binaries.binary[i].data)
