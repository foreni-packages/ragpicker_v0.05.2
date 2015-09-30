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

log = logging.getLogger("CheckTLS")

class CheckTLS(IPlugin, Processing):
    """
    Thread Local Storage (TLS) is a mechanism that allows Microsoft Windows to define data objects that are not automatic (stack) variables, 
    yet are "local to each individual thread that runs the code. Thus, each thread can maintain a different value for a variable declared 
    by using TLS." This information is stored in the PE header. (Windows uses the PE header to store meta information about the executable 
    to load and run the program.) 
    """
    
    def run(self, objfile):
        self.key = "CheckTLS"
        self.score = 0
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            try:
                pe = PE(data=objfile.file_data)
                tlsAdresses = []
                callbacks = self.checkTLS(pe)
                
                if len(callbacks):
                    self.score = 10
                    log.info("TLS callbacks")
                    
                    for cb in callbacks:
                        tlsAdresses.append(hex(cb))
                  
                return tlsAdresses
            except PEFormatError, e:
                log.warn("Error - No Portable Executable or MS-DOS: %s" % e)        
        
        return None
    
    def checkTLS(self, pe):
        callbacks = []
        if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
                    pe.DIRECTORY_ENTRY_TLS and \
                    pe.DIRECTORY_ENTRY_TLS.struct and \
                    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
            callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase 
            idx = 0
            while True:
                func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                if func == 0: 
                    break
                callbacks.append(func)
                idx += 1
        return callbacks