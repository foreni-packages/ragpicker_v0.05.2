# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

from core.abstracts import Report
from yapsy.IPlugin import IPlugin

try:
    from pymongo.connection import Connection
    from pymongo.errors import ConnectionFailure
except ImportError:
    raise Exception("PyMongo is required for working with MongoDB: http://api.mongodb.org/python/current/")

class MongoDB(IPlugin, Report):
    """Stores report in MongoDB."""

    def connect(self):
        """Connects to Mongo database, loads options and set connectors.
        @raise Exception: if unable to connect.
        """
        host = self.options.get("host", "127.0.0.1")
        port = self.options.get("port", 27017)

        try:
            self.conn = Connection(host, port)
            self.db = self.conn.MalwareAnalyse
        except TypeError:
            raise Exception("Mongo connection port must be integer")
        except ConnectionFailure:
            raise Exception("Cannot connect to MongoDB")

    def run(self, results, objfile):
        """Writes report.
        @param results: analysis results dictionary.
        @param objfile: file object
        @raise Exception: if fails to connect or write to MongoDB.
        """
        self.connect()

        #Count query using URL hash and file hash
        url_md5 = results["Info"]["url"]["md5"]
        file_md5 = results["Info"]["file"]["md5"]
        query = { "$and" : [{ "Info.url.md5": { "$in": [url_md5] } }, { "Info.file.md5": { "$in": [file_md5] } }]}
        
        count = self.db.ragpicker.find(query).count()
        #If report available for the file and url -> not insert
        if count == 0:
            # Create a copy of the dictionary. This is done in order to not modify
            # the original dictionary and possibly compromise the following
            # reporting modules.
            report = dict(results)
            # Store the report and retrieve its object id.
            self.db.ragpicker.insert(report)
            
        self.conn.disconnect()
