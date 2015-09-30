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

log = logging.getLogger("CheckEP")
# legit entry point sections
GOOD_EP_SECTIONS = ['.text', '.code', 'CODE', 'INIT', 'PAGE']
    
class CheckEP(IPlugin, Processing):

    def run(self, objfile):
        """
        Alert if the EP section is not in a known good section or if its in the last PE section
        """
        self.key = "CheckEP"
        self.score = 0
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            returnValue = {}
            suspicious = False
            
            try:
                pe = PE(data=objfile.file_data)
                (ep, name, pos) = self.checkEPSection(pe)
                posVsSections = "%d/%d" % (pos, len(pe.sections))
                
                if (name not in GOOD_EP_SECTIONS) or pos == len(pe.sections):
                    self.score = 10
                    suspicious = True
                    
                returnValue = {'EP':hex(ep+pe.OPTIONAL_HEADER.ImageBase), 
                               'Name':name, 
                               'posVsSections':posVsSections,
                               'Suspicious':suspicious}
                    
                return returnValue
            except PEFormatError, e:
                log.warn("Error - No Portable Executable or MS-DOS: %s" % e)        
        
        return None
    
    def checkEPSection(self, pe):
        """ Determine if a PE's entry point is suspicious """
        name = ''
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pos = 0
        for sec in pe.sections:
            if (ep >= sec.VirtualAddress) and \
               (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
                name = sec.Name.replace('\x00', '')
                break
            else: 
                pos += 1
        return (ep, name, pos)