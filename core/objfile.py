# Copyright (C) 2013 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import os
import magic
import hashlib
import tempfile
import logging
import base64
from urlparse import urlparse

FILE_CHUNK_SIZE = 16 * 1024
log = logging.getLogger(__name__)

class ObjFile:
    
    permitted_types = ['PDF','Zip','PE32', 'MS-DOS']
    
    def __init__(self, url):
        self.url = url
        
    def setFileData(self, file_data):
        self.file_data = file_data
        
        #Tmp-File erzeugen
        try:        
            self.temp_file = self._get_tmpFileName()
            
            file = open(self.temp_file, 'wb')
            file.write(file_data)
            file.seek(0)
            file.close
            
            #File consistency check
            tempMd5 = self._md5Checksum(self.temp_file)
            dataMd5 = hashlib.md5(file_data).hexdigest()
            
            log.debug("DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5))
            
            if dataMd5 != tempMd5:
                log.error("File not consistent DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5))
                raise Exception("File not consistent DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5))             
            
            log.info("temp_file=%s" % self.temp_file)  
        except Exception, e:
            log.error("Error - Unable to create tempFile")
            raise Exception("Error - Unable to create tempFile") 
        
    def _get_tmpFileName(self):
        tmppath = tempfile.gettempdir()
        targetpath = os.path.join(tmppath, "ragpicker-tmp")
        if not os.path.exists(targetpath):
            os.mkdir(targetpath)
            
        tf = tempfile.NamedTemporaryFile(dir=targetpath, suffix='.virus', prefix='ragpicker_',)
        tempfileName = tf.name
        tf.close()
            
        log.debug("tempfileName=%s" % tempfileName)
        return tempfileName
    
    def _md5Checksum(self, filePath):
        with open(filePath, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(FILE_CHUNK_SIZE)
                if not data:
                    break
                m.update(data)
            
            md5 = m.hexdigest()
            log.debug("%s MD5= %s" % (filePath, md5))
            return md5
    
    def close(self):  
        try:
            log.info("close tmpFile: %s" % self.temp_file)
            os.remove(self.temp_file)
        except Exception:
            exit
          
        
    def get_url_hostname(self):
        o = urlparse(self.url)
        return o.hostname
    
    def get_url_protocol(self):
        o = urlparse(self.url)
        return o.scheme
    
    def get_url_port(self):
        o = urlparse(self.url)
        return o.port  
    
    def get_type(self):
        """Get MIME file type.
        @return: file type.
        """
        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.file(self.temp_file)
        except:
            try:
                file_type = magic.from_file(self.temp_file)
            except:
                try:
                    import subprocess
                    file_process = subprocess.Popen(['file', '-b', self.temp_file],
                                                    stdout = subprocess.PIPE)
                    file_type = file_process.stdout.read().strip()
                except:
                    return None
        finally:
            try:
                ms.close()
            except:
                pass

        file_type = file_type.split(' ')[0]
        
        return file_type
    
    def get_fileB64encode(self):  
        with open(self.temp_file, "rb") as raw_file:
            encoded_file = base64.b64encode(raw_file.read())
        return encoded_file
    
    def get_fileMd5(self):
        md5 = hashlib.md5(self.file_data).hexdigest()
        return str(md5)

    def get_fileSha1(self):
        sha1 = hashlib.sha1(self.file_data).hexdigest()
        return str(sha1)
    
    def get_fileSha256(self):
        sha256 = hashlib.sha256(self.file_data).hexdigest()
        return str(sha256)
        
    def get_urlMd5(self):
        md5 = hashlib.md5(self.url).hexdigest()
        return str(md5)      
    
    def is_permittedType(self):
        filetype = self.get_type()
        
        for x in self.permitted_types:
            if filetype.__contains__(x):
                return True
        return False
    
    def get_size(self):
        """Get file size.
        @return: file size.
        """
        return os.path.getsize(self.temp_file)    
    
    def file_extension(self):
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(self.file_data)
        
        if not file_type:
            return None
    
        if "DLL" in file_type:
            return "dll"
        elif "PE32" in file_type or "MS-DOS" in file_type:
            return "exe"
        elif "Zip" in file_type:
            return "zip"
        elif "PDF" in file_type:
            return "pdf"
        elif "Rich Text Format" in file_type or "Microsoft Office Word" in file_type:
            return "doc"
        elif "Microsoft Office Excel" in file_type:
            return "xls"
        elif "HTML" in file_type:
            return "html"
        else:
            return None