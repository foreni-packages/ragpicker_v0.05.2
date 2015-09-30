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

log = logging.getLogger("ProcessingPESectionInfo")

class SectionInfo(IPlugin, Processing):
    
    def run(self, objfile):
        """Returns the PE Sections Informations.
        """
        self.key = "SectionInformations"
        self.score = -1
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            returnValue = {}
            size = objfile.get_size()
            
            try:
                pe = PE(data=objfile.file_data)
                
                returnValue["NumberOfSections"] = pe.FILE_HEADER.NumberOfSections
                
                i = 0
                sections = []
                for section in pe.sections:
                    i += 1
                    info = {}
                    sname = section.Name.replace("\x00", "")
                    entropy = round(section.get_entropy(),1)
                    info["name"] = sname
                    info["md5"] = section.get_hash_md5()                   
                    info["virtualAddress"] = hex(section.VirtualAddress)
                    info["virtualSize"] = hex(section.Misc_VirtualSize)
                    info["sizeOfRawData"] = section.SizeOfRawData
                    
                    if section.SizeOfRawData == 0 or (entropy > 0 and entropy < 1) or entropy > 6:
                        self.score += 10
                        entropy = str(entropy) + " [SUSPICIOUS]"
                       
                    info["entropy"] = entropy     
                    sections.append(info)
                        
                returnValue["Sections"] = sections 
                    
                if self.score > 10:
                    self.score = 10    
                    
                return returnValue
            except PEFormatError, e:
                log.warn("Error - No Portable Executable or MS-DOS: %s" % e)        
        
        return None