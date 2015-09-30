# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import utils.pefile
from utils.pefile import PE
from utils.pefile import PEFormatError
from utils.peutils import is_probably_packed
from core.abstracts import Processing
from core.constants import RAGPICKER_VERSION

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingInfo")

class info(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "Info"
        self.score = -1
        isProbablyPacked = False
        returnValue = {}
        
        infos = {}
        infos["ragpicker_version"] = RAGPICKER_VERSION
        infos["started"] = self.task["started_on"]                       
        returnValue["analyse"] = infos 
        
        infos = {}
        infos["extension"] = objfile.file_extension()    
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            try:
                pe = PE(data=objfile.file_data)
                
                isProbablyPacked = is_probably_packed(pe)
                
                infos["DLL"] = pe.is_dll()
                infos["EXE"] = pe.is_exe()
                infos["DRIVER"] = pe.is_driver()
                infos["isProbablyPacked"] = isProbablyPacked
                
                if self.getDigitalSignature(pe):
                    infos["digitalSignature"] = "SignedFile"
                else:
                    infos["digitalSignature"] = "UnsignedFile"
                    
                if isProbablyPacked:
                    self.score = 10
            except PEFormatError, e:
                log.warn("Error - No Portable Executable: %s" % e)         
        
        infos["size"] = objfile.get_size()
        infos["type"] = objfile.get_type()
        infos["md5"] = objfile.get_fileMd5()
        infos["sha1"] = objfile.get_fileSha1()
        infos["sha256"] = objfile.get_fileSha256()  
                
        returnValue["file"] = infos 
        
        infos = {}
        infos["url"] = objfile.url   
        infos["md5"] = objfile.get_urlMd5()
        infos["hostname"] = objfile.get_url_hostname()
        infos["protocol"] = objfile.get_url_protocol()
        infos["port"] = objfile.get_url_port() 
        returnValue["url"] = infos 
            
        return returnValue

    def getDigitalSignature(self, pe):
        """Extracts the digital signature from file
           Returns the signature
        """
        
        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[utils.pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[utils.pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    
        if address == 0:
            log.info('source file not signed')
            return None
        
        signature = pe.write()[address+8:]
        
        return signature