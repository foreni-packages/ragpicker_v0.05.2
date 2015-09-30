# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
from core.abstracts import Processing
from utils.pefile import PE
from utils.pefile import PEFormatError

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingImports")

class Imports(IPlugin, Processing):
    
    def run(self, objfile):
        """Imported DLLs and API
        """
        self.key = "Imports"
        self.score = -1
        returnValue = []
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            try:
                pe = PE(data=objfile.file_data)
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = {}
                    dllImport = []
                    for imp in entry.imports:
                        if imp.name: dllImport.append(imp.name)
                        
                    dll["name"] = entry.dll
                    dll["imports"] = dllImport
                    returnValue.append(dll)         
            except PEFormatError, e:
                log.warn("Error - No Portable Executable: %s" % e) 
        
        return returnValue