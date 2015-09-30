# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import datetime
import threading
import urllib2
import logging
import os
from urlparse import urlparse
from collections import OrderedDict
from core.constants import RAGPICKER_ROOT
from core.config import Config
from core.objfile import ObjFile

try:
    from yapsy.PluginManager import PluginManager
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger(__name__)

class Worker(threading.Thread):
    """Threaded File Worker"""
 
    def __init__(self, queue, threadName):
        threading.Thread.__init__(self)
        self.totalScore = 0     # sum of scores
        self.numberScores = 0   # number of scores entered
        self.queue = queue
        self.threadName = threadName
        self.task = dict()
        self.cfgProcessing = Config(os.path.join(RAGPICKER_ROOT, 'config', 'processing.conf'))
        self.cfgReporting = Config(os.path.join(RAGPICKER_ROOT, 'config', 'reporting.conf'))
        self.cfgCrawler = Config(os.path.join(RAGPICKER_ROOT, 'config', 'crawler.conf'))
 
    def run(self):
        while True:
            # gets the url from the queue
            url = self.queue.get()

            #URLs not being processing
            if not self._check_urlBlackList(url):
                try:
                    objfile = ObjFile(url)                    
                    #Zeitmessung Start
                    self.task.update({"started_on":datetime.datetime.now()})
        
                    #Download the file
                    objfile = self._process_url(url)
                    
                    if objfile.is_permittedType():
                        #Run processing-plugins
                        results = self._run_processing(objfile)
                        
                        if results:
                            log.debug(results)     
                            # Run report-plugins                     
                            self._run_reporting(results, objfile)         
                    else:
                        log.warn("url %s does not provide any allowed file type (%s)" % (url, objfile.get_type()))
                except Exception, e:
                    import traceback
                    log.warn(traceback.print_exc())
                    log.warn("Thread("+self.threadName+") - %s - Error parsing %s" % (e, url))
                finally:   
                    if objfile:
                        #File object close
                        objfile.close()                  
               
            # send a signal to the queue that the job is done
            self.queue.task_done()
            
    def _check_urlBlackList(self, url):
        
        try:
            urlBlackList = self.cfgCrawler.get('urlBlackList')
        except Exception:
            log.error("urlBlackList not found in configuration file")
            return 

        urls = map(lambda s: s.strip('\''), urlBlackList.get('url').split(','))
        
        o = urlparse(url)
        hostname = o.hostname

        if hostname in urls:
            log.info("%s in Url-BlackList: %s" % (hostname, urls))
            return True
            
        return False
        
    
    def _run_reporting(self, results, objfile):
        #options
        options = dict()
        
        # Build the PluginManager
        reportingPluginManager = PluginManager()
        reportingPluginManager.setPluginPlaces(["reporting"])
        reportingPluginManager.collectPlugins()
        
        # Trigger run from the "Reporting" plugins
        for pluginInfo in reportingPluginManager.getAllPlugins():
            reportingModul = pluginInfo.plugin_object
            reportingModul.set_task(self.task)
            
            # Give it the the relevant reporting.conf section.
            try:
                options = self.cfgReporting.get(pluginInfo.name)
                reportingModul.set_options(options)
            except Exception:
                log.error("Reporting module %s not found in configuration file", pluginInfo.name)  
                
            # If the processing module is disabled in the config, skip it.
            if not options.enabled:
                continue
            
            log.debug("Run Reporting: " + pluginInfo.name)
            
            try:
                # Run the Reporting module
                reportingModul.run(results, objfile)
            except Exception as e:
                log.exception("Failed to run the reporting module \"%s\":",
                              reportingModul.__class__.__name__)
            
    def _run_processing(self, objfile):
        # This is the results container. It's what will be used by all the
        # reporting modules to make it consumable by humans and machines.
        # It will contain all the results generated by every processing
        # module available. Its structure can be observed throgh the JSON
        # dump in the the analysis' reports folder.
        # We friendly call this "fat dict".
        results = {}
        #options
        options = dict()
        
        # Build the PluginManager
        processPluginManager = PluginManager()
        processPluginManager.setPluginPlaces(["processing"])
        processPluginManager.collectPlugins()
        
        # Trigger run from the "Processing" plugins
        for pluginInfo in processPluginManager.getAllPlugins():
            processModul = pluginInfo.plugin_object
            
            #Config for processing module
            try:
                options = self.cfgProcessing.get(pluginInfo.name)
                processModul.set_options(options)
            except Exception:
                log.error("Processing module %s not found in configuration file", pluginInfo.name)  
                
            # If the processing module is disabled in the config, skip it.
            if not options.enabled:
                continue
            
            log.debug("Run Processing: " + pluginInfo.name)
            processModul.set_task(self.task)
        
            try:
                # Run the processing module and retrieve the generated data to be
                # appended to the general results container.
                data = processModul.run(objfile)
    
                # If it provided some results, append it to the big results
                # container.
                if data:
                    results.update({processModul.key : data})
                    
                #set scoring from processModul
                if processModul.score > -1:
                    log.info("-------------------------------------------------- Score %s: %s" %  (pluginInfo.name, str(processModul.score)))
                    self._setScore(processModul.score)
            except Exception as e:
                log.exception("Failed to run the processing module \"%s\":",
                              processModul.__class__.__name__)

        #dictionary sorted by key
        results = OrderedDict(sorted(results.items(), key=lambda t: t[0]))
        
        #calculate scoring
        scoring = self._getScoring()
        results.update({"score" : scoring})
        log.info("SCORING: " + scoring)
        
        return results
 
    def _process_url(self, url):
        #Crawler config load
        cfgCrawler = Config(os.path.join(RAGPICKER_ROOT, 'config', 'crawler.conf')).get("clientConfig")
        
        data = None
        headers = {   
            'User-Agent': cfgCrawler.get("browser_user_agent", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)"),
            'Accept-Language': cfgCrawler.get("browser_accept_language", "en-US"),
        }
        
        request = urllib2.Request(url, data, headers)
    
        try:
            url_dl = urllib2.urlopen(request, timeout=30).read()
        except Exception, e:
            raise IOError("Thread("+self.threadName+") - %s - Error parsing %s" % (e, url)) 
        
        try:
            objfile = ObjFile(url)
            objfile.setFileData(url_dl)
        except Exception, e:
            raise Exception("Thread("+self.threadName+") - %s - Error create ObjFile %s" % (e, url)) 
 
        return objfile
    
    def _setScore(self, score):
        self.totalScore = self.totalScore + score
        self.numberScores = self.numberScores + 1
        
    def _getScoring(self):
        if self.numberScores != 0: # division by zero would be a run-time error
            average = float(self.totalScore) / self.numberScores
            average = round(average, 1)
        else:
            #No scores were entered
            average = 0
           
        return str(average)