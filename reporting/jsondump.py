# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import os
import json
import codecs
import tempfile
import logging
from core.abstracts import Report

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger(__name__)

class JsonDump(IPlugin, Report):
    """Saves analysis results in JSON format."""
    
    def run(self, results, objfile):
        """Writes report.
        @param results: results dict.
        @param objfile: file object
        @raise Exception: if fails to write report.
        """
        dumpdir=self.options.get("dumpdir", None)

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
        
        try:
            url_md5 = results["Info"]["url"]["md5"]
            file_md5 = results["Info"]["file"]["md5"]
            jfile = url_md5 + "_" + file_md5 + ".json"
            
            if not os.path.exists(dumpdir+jfile):
                report = codecs.open(os.path.join(dumpdir, jfile), "w", "utf-8")
                json.dump(results, report, default=self.date_handler, sort_keys=False, indent=4)
                report.close()
        except (UnicodeError, TypeError, IOError) as e:
            log.error("Failed to generate JSON report: %s" % results)
            raise Exception("Failed to generate JSON report: %s" % e)        