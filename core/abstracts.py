# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import urllib2
import re
import hashlib

try:
    from BeautifulSoup import BeautifulSoup as bs
except ImportError:
    raise ImportError, 'Beautiful Soup parser: http://www.crummy.com/software/BeautifulSoup/'


log = logging.getLogger(__name__)

class Processing(object):
    """Base abstract class for Processing-Module."""

    def __init__(self):
        self.options = None
        self.task = None
        
    def set_options(self, options):
        """Set options.
        @param options: options dict.
        """
        self.options = options
        
    def set_task(self, task):
        """Add task information.
        @param task: task dictionary.
        """
        self.task = task           

    def run(self, objfile):
        """Start report processing. 
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError
    
    # beautifulsoup parser
    def parse(self, url):
        request = urllib2.Request(url)
        request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
        try:
            http = bs(urllib2.urlopen(request, timeout=30))
        except Exception, e:
            log.error("%s - Error parsing %s" % (e, url))
            return
        return http    
    
class Report(object):
    """Base abstract class for reporting module."""
    order = 1

    def __init__(self):
        self.options = None
        self.task = None
        
    def set_task(self, task):
        """Add task information.
        @param task: task dictionary.
        """
        self.task = task              

    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options

    def run(self, results, objfile):
        """Start report processing.
        @param results: results dict.
        @param objfile: file object
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError
    
    def date_handler(self, obj):
        return obj.isoformat() if hasattr(obj, 'isoformat') else obj     

class Crawler(object):
    """Base abstract class for Malware Crawler."""
            
    def __init__(self):
        self.options = None            
        
    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options
        
    def storeURL(self, url):
        try:
            if not re.match('http',url):
                url = 'http://'+url
            
            md5 = hashlib.md5(url).hexdigest()
            self.mapURL[md5] = url      
        except Exception as e:
            log.error('Error in storeURL: %s', e) 
            
    def run(self):
        """Start report processing. 
        @return: Returns a Map of URL-MD5 Hash and HTTP-URLs
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError    
    
    # beautifulsoup parser
    def parse(self, url):
        request = urllib2.Request(url)
        request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
        try:
            http = bs(urllib2.urlopen(request, timeout=60))
        except Exception, e:
            log.error("%s - Error parsing %s" % (e, url))
            return
        return http 