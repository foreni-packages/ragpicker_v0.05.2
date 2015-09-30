# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os
from utils.pefile import PE
from utils.pefile import PEFormatError
from utils.peutils import SignatureDatabase
from core.abstracts import Processing
from core.constants import RAGPICKER_ROOT

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingPEID")

class PEID(IPlugin, Processing):
    
    def run(self, objfile):
        """Gets PEID signatures.
        @return: matched signatures or None.
        """
        self.key = "PEID"
        self.score = -1
        
        if objfile.get_type() == 'PE32' or objfile.get_type() == 'MS-DOS':
            try:
                pe = PE(data=objfile.file_data)
                signatures = SignatureDatabase(os.path.join(RAGPICKER_ROOT, 'utils', 'userdb.txt'))
                match = signatures.match(pe,ep_only = True)
                if match:
                    log.info("PEID match: %s" % match)
                    self.score = 10
                return match
            except PEFormatError, e:
                log.warn("Error - No Portable Executable: %s" % e)        
        
        return None