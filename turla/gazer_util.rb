# This file is a metasm script for extracting and decrypting resources of 
# Turla Gazer orchestrators. It only works on 64bits samples.
# Details about Gazer can be found at 
# https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf
#
# For feedback or questions contact us at: github@eset.com
# https://github.com/eset/malware-research/
#
# Author:
# ESET Research
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
#encoding: ASCII-8BIT

require 'metasm'
include Metasm
require 'pp'
require 'win32/registry'

class GazerUtil
    def initialize(infile)  

        puts ''
        puts '##################################'
        puts '######### Gazer Utility ##########'
        puts '##################################'
        puts ''

        @infile = infile

        # patch binary
        IO.copy_stream(infile, infile + "-patched")
        File.open(infile + "-patched", "r+") do |f|
            f.seek(0x3C, IO::SEEK_SET)
            offset_pe = f.read(4).unpack('L').first
            f.seek(offset_pe, IO::SEEK_SET)
            f.seek(0x18, IO::SEEK_CUR)
            magic = f.read(4).unpack('L').first
            if (magic & 0xFFFF) != 0x20b
                puts "[-] PE32 binaries not supported yet"
                exit
            end
            f.seek(offset_pe, IO::SEEK_SET)
            f.seek(0x16, IO::SEEK_CUR) # patch FileHeader.Characteristics to remove "DLL flag"
            f.write("\x22\x00")
            f.seek(offset_pe, IO::SEEK_SET)
            f.seek(0x5e, IO::SEEK_CUR) # patch DllCanMove flag
            f.write("\x00\x00")
            f.close()
       end

        # create directory to store the resources 
        filepath = File.dirname(infile)
        Dir.chdir(filepath)
        Dir.mkdir(infile + ".extract") unless File.exist?(infile + ".extract")

        # debug binary
        pe = PE.decode_file(infile + "-patched")
        
        @pe_base = pe.optheader.image_base
        @code_size = pe.optheader.image_size
    
        # breakpoint on OEP
        @dbg = OS.current.create_process(infile + "-patched").debugger
        @dbg.bpx(@pe_base + pe.optheader.entrypoint, true) {oep_callback}
        @dbg.run_forever()
        puts 'done'
    end
    
    def get_addresses(module_name, func_name)
        results = []
        @dbg.symbols.each{|m|
            if m[1].casecmp(func_name) == 0
                puts "[+] symbol found : #{m[1]} @ #{m[0].to_s(16)}"
                results << m[0]
            end
        }
        results
    end

    def findResourceW_callback
        # patch hModule
        @dbg.ctx[:rcx] = 0
        @dbg.ctx[:rbx] = 0
        rdx = @dbg.resolve("rdx")
        $rsrc_id = rdx
    end

    def patch_bIsStorageEmpty
        puts "[+] bIsStorageEmpty patched" 
        @dbg.ctx[:rax] = 1
    end

    def search_bIsStorageEmpty
        puts "Searching for code pattern..."
        end_addr = @pe_base + @code_size
        for i in @pe_base..end_addr
            if @dbg.memory_read_int(i) == 0x0001b090ff018b48
                return i+21
            end 
        end
        0
    end
    def patch_fdwReason
        puts "[+] fdwReason patched"
        @dbg.ctx[:rsi] = 1
        @dbg.ctx[:rbx] = 1
    end

    def search_encrypt_function
        puts "Searching for code pattern..."
        end_addr = @pe_base + @code_size
        for i in @pe_base..end_addr
            if @dbg.memory_read_int(i) == 0x8b48c28b4cf28b48
                return i
            end 
        end
        0
    end

    def search_RegStorage_Init
        puts "Searching for code pattern..."
        end_addr = @pe_base + @code_size
        for i in @pe_base..end_addr
            if @dbg.memory_read_int(i) == 0x0851894828ec8348
                return i
            end 
        end
        0
    end

    def dump_RegStorage
        addr_data = @dbg.resolve("r8")
        buf = @dbg[addr_data,0x200]
        @filename = "VFS_path.dumped"
        puts "[+] decrypted VFS path extracted"
        File.write(@infile + ".extract/" + @filename, buf)
    end

    def dump_rsrc       
        addr_data = @dbg.memory_read_int(@dbg.resolve("rcx"))
        addr_size = @dbg.resolve("rdx")
        size = @dbg.memory_read_int(addr_size)
        buf = @dbg[addr_data,size]
        @filename = $rsrc_id.to_s() + ".dumped"
        puts "[+] decrypted resource #{$rsrc_id} extracted"
        File.write(@infile + ".extract/" + @filename, buf)
        if $rsrc_id == 104
            exit
        end
    end

    def oep_callback
        puts "[+] breakpoint hit OEP @ #{@dbg.ip.to_s(16)}"    

        addr = search_RegStorage_Init()
        if addr != 0
            puts "[+] RegStorage_Init found @#{addr.to_s(16)}"
            @dbg.bpx(addr, true) {dump_RegStorage}
        else
            puts "[-] RegStorage_Init not found"
            exit
        end

        addresses = get_addresses("kernel32.dll", "GetProcessHeaps")
        if addresses != 0
            addresses.each{|addr|
                @dbg.bpx(addr, true) {patch_fdwReason}
                puts "[+] bpx put @#{addr.to_s(16)}"
        }
        else
            puts "[-] Function GetProcessHeaps not found"
            exit
        end 

        addresses = get_addresses("kernel32.dll", "FindResourceW")
        if addresses != 0
            addresses.each{|addr|
                @dbg.bpx(addr, false) {findResourceW_callback}
                puts "[+] bpx put @#{addr.to_s(16)}"
        }
        else
            puts "[-] Function FindResourceW not found"
            exit
        end
        
        addr = search_encrypt_function()
        if addr != 0
            puts "[+] Encrypt function found @#{addr.to_s(16)}"
            @dbg.bpx(addr, false) {dump_rsrc}
        else
            puts "[-] Encrypt function not found"
            exit
        end

        addr = search_bIsStorageEmpty()
        if addr != 0
            puts "[+] bIsStorageEmpty found @#{addr.to_s(16)}"
            @dbg.bpx(addr, true) {patch_bIsStorageEmpty}
        else
            puts "[-] bIsStorageEmpty not found"
            exit
        end
    end    

end

if __FILE__ == $0
    fn = ARGV.shift   # argv[1]
    abort 'Usage : extract <Gazer Orchestrator>' if not File.exist?(fn)
    GazerUtil.new(fn)
end
