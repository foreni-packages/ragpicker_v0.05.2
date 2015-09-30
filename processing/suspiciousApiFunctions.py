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

log = logging.getLogger("ProcessingSuspiciousApiFunctions")

## Suspicious Functions API and Sections
alerts = [#A
          'accept', 'AddCredentials',
          #B 
          'bind', 
          #C
          'CertDeleteCertificateFromStore', 'CheckRemoteDebuggerPresent', 'closesocket', 'connect', 'ConnectNamedPipe', 
          'CopyFile', 'CreateFile', 'CreateProcess', 'CreateToolhelp32Snapshot', 'CreateFileMapping', 'CreateRemoteThread', 
          'CreateDirectory', 'CreateService', 'CreateThread', 'CryptEncrypt', 
          #D
          'DeleteFile', 'DeviceIoControl', 'DisconnectNamedPipe', 'DNSQuery', 
          #E
          'EnumProcesses', 'ExitThread', 
          #F
          'FindWindow', 'FindResource', 'FindFirstFile', 'FindNextFile', 'FltRegisterFilter', 'FtpGetFile', 'FtpOpenFile', 
          #G
          'GetAsyncKeyState', 'GetCommandLine', 'GetThreadContext', 'GetDriveType', 'GetFileSize', 'GetFileAttributes', 
          'GetHostByAddr', 'GetHostByName', 'GetHostName', 'GetKeyState', 'GetModuleHandle', 'GetProcAddress', 
          'GetTempFileName', 'GetTempPath', 'GetTickCount', 'GetUpdateRect', 'GetUpdateRgn', 'GetUserNameA', 'GetUrlCacheEntryInfo', 
          'GetComputerName', 'GetVersionEx', 'GetModuleFileName', 'GetStartupInfo', 'GetWindowThreadProcessId', 
          #H
          'HttpOpenRequest', 'HttpOpenRequestA', 'HttpSendRequest', 'HttpSendRequestA', 'HttpQueryInfo', 
          #I
          'IcmpSendEcho', 'ioctlsocket', 'IsDebuggerPresent', 'InternetCloseHandle', 'InternetConnect', 'InternetCrackUrl', 
          'InternetQueryDataAvailable', 'InternetGetConnectedState', 'InternetOpen', 'InternetQueryDataAvailable', 
          'InternetQueryOption', 'InternetReadFile', 'InternetWriteFile', 
          #L
          'LdrLoadDll', 'LoadLibrary', 'LoadLibraryA', 'LockResource', 'listen', 
          #M
          'MapViewOfFile', 
          #O
          'OutputDebugString', 'OpenFileMapping', 'OpenProcess', 
          #P
          'Process32First', 'Process32Next', 
          #R
          'recv', 'ReadProcessMemory', 'RegCloseKey', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue', 'RegEnumKey', 'RegOpenKey', 
          #S
          'send', 'sendto', 'SetKeyboardState', 'SetWindowsHook', 'ShellExecute', 'Sleep', 'socket', 'StartService', 
          #T
          'TerminateProcess', 
          #U
          'UnhandledExceptionFilter', 'URLDownload', 'URLDownloadToFile', 'URLDownloadToFileA', 
          #V
          'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx',
          #W
          'WinExec', 'WriteProcessMemory', 'WriteFile', 'WSAIoctl', 'WSASend', 'WSASocket', 'WSASocketA', 'WSAStartup', 
          #Z
          'ZwQueryInformation']

class SuspiciousApiFunctions(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "SuspiciousApiFunctions"
        self.score = 0
        apiFunctions = []

        if objfile.get_type() == 'PE32':
            try:
                pe = PE(data=objfile.file_data)
                
                for lib in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in lib.imports:
                            if (imp.name != None) and (imp.name != ""):
                                for alert in alerts:
                                    if imp.name.startswith(alert):
                                        apiFunctions.append(imp.name)
                                        
                countApiFunctions = len(apiFunctions)
                if countApiFunctions > 2 and countApiFunctions < 5:
                    self.score = 5
                elif countApiFunctions > 5:
                    self.score = 8
                elif countApiFunctions > 10:
                    self.score = 10
            except PEFormatError, e:
                log.warn("Error - No Portable Executable: %s" % e)                 

        return apiFunctions