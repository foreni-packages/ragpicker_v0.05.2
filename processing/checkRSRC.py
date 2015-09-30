# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import magic
import utils.pefile as pefile
from utils.pefile import PE
from utils.pefile import PEFormatError
from core.abstracts import Processing

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("CheckRSRC")

class CheckRSRC(IPlugin, Processing):
    """
    .rsrc section
    
    This section contains the resources of a PE. Resources are for instance icons, menus, dialogs, version information, font information, 
    but it also might be anything arbitrary. The reason I chose the resource section first, is that this is a good candiate for adding data 
    to the PE file. The resource section has a multiple-level binary-sorted tree structure. The tree can have up to 2^31 levels, 
    but it is a convention that Windows uses three levels: 
        Type
        Name
        Language
    """
    def run(self, objfile):
        self.key = "CheckRSRC"
        self.score = -1
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            returnValue = []
            
            try:
                pe = PE(data=objfile.file_data)
                resources = self.check_rsrc(pe)
                
                if len(resources):
                    for rsrc in resources.keys():
                        (name,rva,size,type,lang,sublang) = resources[rsrc]
                        resource = {}
                        resource["name"] = name
                        resource["RVA"] = hex(rva)
                        resource["Size"] = hex(size)
                        resource["Lang"] = lang
                        resource["Sublang"] = sublang
                        resource["Type"] = type
                        returnValue.append(resource)
                          
                return returnValue
            except PEFormatError, e:
                log.warn("Error - No Portable Executable or MS-DOS: %s" % e)        
        
        return None
    
    def check_rsrc(self, pe):
        ret = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            i = 0
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = "%s" % resource_type.name
                else:
                    name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = "%d" % resource_type.struct.Id
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                filetype = self.get_type(data)
                                lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                                sublang = pefile.get_sublang_name_for_lang( resource_lang.data.lang, resource_lang.data.sublang )
                                ret[i] = (name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, filetype, lang, sublang)
                                i += 1
        return ret     
    
    def get_type(self, file_data):
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        filetype = ms.buffer(file_data)
        filetype = filetype.split(' ')[0]
        return filetype   