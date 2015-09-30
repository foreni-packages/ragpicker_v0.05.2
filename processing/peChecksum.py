# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
from utils.pefile import PE
from utils.pefile import PEFormatError
from core.abstracts import Processing

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("PEChecksum")

class PEChecksum(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "PEChecksum"
        self.score = 0
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            returnValue = {}
            suspicious = False
            
            try:
                pe = PE(data=objfile.file_data)
                
                claimed = hex(pe.OPTIONAL_HEADER.CheckSum)
                actual  = hex(pe.generate_checksum())
                
                if actual != claimed:
                    suspicious = True
                    self.score = 10
                    
                log.info("Claimed: %s, Actual: %s %s" % 
                        (claimed, actual, "[SUSPICIOUS]" if suspicious else ""))
                
                returnValue = {'Claimed':claimed, 
                               'Actual':actual, 
                               'Suspicious':suspicious}
                
                return returnValue
            except PEFormatError, e:
                log.warn("Error - No Portable Executable or MS-DOS: %s" % e)        
        
        return None