# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import os
import logging
import tempfile
from core.abstracts import Report

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger(__name__)

class FileDump(IPlugin, Report):
    """Save downloaded file on the file system"""
    
    def run(self, results, objfile):
        dumpdir=self.options.get("dumpdir", None)
        suffix=self.options.get("suffix", None)

        if not dumpdir:
            raise Exception("dumpdir not configured, skip")
         
        try:
            if not os.path.exists(dumpdir):
                os.makedirs(dumpdir)  
            d = tempfile.mkdtemp(dir=dumpdir)
        except Exception as e:
            raise Exception('Could not open %s for writing (%s)', dumpdir, e)
        else:
            os.rmdir(d)
        
        dest = dumpdir + objfile.get_type()
        
        if objfile.file_extension():
            file_extension = '.' + objfile.file_extension() + suffix
        else:
            file_extension = suffix
            
        fpath = dest + '/' + objfile.get_fileMd5() + file_extension
        
        if objfile.is_permittedType():
            if not os.path.exists(dest):
                os.makedirs(dest)
    
            if not os.path.exists(fpath):
                file = open(fpath, 'wb')
                file.write(objfile.file_data)
                file.close
                log.info("Saved file type %s with md5: %s" % (objfile.get_type(),objfile.get_fileMd5()+'.'+objfile.file_extension()))
            
            return fpath
        return None