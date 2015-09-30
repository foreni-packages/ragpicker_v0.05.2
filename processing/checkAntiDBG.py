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

log = logging.getLogger("ProcessingCheckAntiDBG")

antidbgs = ['CheckRemoteDebuggerPresent', 'FindWindow', 'GetWindowThreadProcessId', 'IsDebuggerPresent', 
            'OutputDebugString', 'Process32First', 'Process32Next', 'TerminateProcess',  
            'UnhandledExceptionFilter', 'ZwQueryInformation']

class CheckAntiDBG(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "AntiDBG"
        self.score = 0
        returnValue = {}
        antiDbgApi = []
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            try:
                pe = PE(data=objfile.file_data)

                for lib in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in lib.imports:
                            if (imp.name != None) and (imp.name != ""):
                                for antidbg in antidbgs:
                                    if imp.name.startswith(antidbg):
                                        antiDbgApi.append(imp.name)
                
                if len(antiDbgApi) > 0:
                    self.score = 8
                    returnValue = {'Anti_Debug' : 'Yes', 'API_Anti_Debug' : antiDbgApi}
                else:
                    returnValue = {'Anti_Debug' : 'No', 'API_Anti_Debug' : ['No suspicious API Anti Debug']}
            except PEFormatError, e:
                log.warn("Error - No Portable Executable: %s" % e) 
        
        return returnValue