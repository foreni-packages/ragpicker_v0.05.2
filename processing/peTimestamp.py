# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import time
from utils.pefile import PE
from utils.pefile import PEFormatError
from core.abstracts import Processing

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("PETimestamp")

class PETimestamp(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "PETimestamp"
        self.score = 0
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            timeStamp = None
            
            try:
                pe = PE(data=objfile.file_data)
                peTimeDateStamp = pe.FILE_HEADER.TimeDateStamp
                timeStamp = '0x%-8X' % (peTimeDateStamp)
                try:
                    timeStamp += ' [%s UTC]' % time.asctime(time.gmtime(peTimeDateStamp))
                    peYear = time.gmtime(peTimeDateStamp)[0]
                    thisYear = time.gmtime(time.time())[0]
                    if peYear < 2000 or peYear > thisYear:
                        timeStamp += " [SUSPICIOUS]"
                        self.score = 10
                except:
                    timeStamp += ' [SUSPICIOUS]'
                    self.score = 10
                
                return timeStamp
            except PEFormatError, e:
                log.warn("Error - No Portable Executable or MS-DOS: %s" % e)        
        
        return None