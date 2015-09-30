# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
from core.abstracts import Processing

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingCheckAntiVM")

VM_Sign = {
    "Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
    "VirtualPc trick":"\x0f\x3f\x07\x0b",
    "VMware trick":"VMXh",
    "VMCheck.dll":"\x45\xC7\x00\x01",
    "VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
    "Xen":"XenVMM",
    "Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
    "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
    "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
    }

class CheckAntiVM(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "AntiVM"
        self.score = 5
        antiVMTricks = []
        CountTricks = 0
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            with open(objfile.temp_file, "rb") as f:
                buf = f.read()
                for trick in VM_Sign:
                    if buf.find(VM_Sign[trick][::-1]) > -1:
                        log.debug("Anti VM:\t", trick)
                        antiVMTricks.append(trick)
                        CountTricks = CountTricks +1
            
            if CountTricks == 0:
                log.debug("Anti VM:\tNone")
                antiVMTricks.append("None")
                self.score = 0
        return antiVMTricks