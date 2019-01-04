UPnP Hunter
===================
```
 ____ _____________     __________    ___ ___               __                
|    |   \______   \____\______   \  /   |   \ __ __  _____/  |_  ___________
|    |   /|     ___/    \|     ___/ /    ~    \  |  \/    \   __\/ __ \_  __ \
|    |  / |    |  |   |  \    |     \    Y    /  |  /   |  \  | \  ___/|  | \/
|______/  |____|  |___|  /____|      \___|_  /|____/|___|  /__|  \_____>__|   
                       \/                  \/            \/                 
```

# Description
UPnP Hunter is a simple Python script which could be useful to find active UPnP 
services/devices running on the specified target IP and extract the related SOAP 
requests. Then is possible use them to interact with the UPnP services via the 
preferred tools (i.e. an HTTP fuzzer).

# Install
Just clone or download this repository.


# Usage
To get a list of basic options use:

    $ UPnPHunter.py -h


To launch the script with minimal options run:

    $ UPnPHunter.py <TARGET_CIDR>

where <TARGET_CIDR> is a IPv4 subnet in CIDR notation. By default the results will be 
prompted on standard output (as list of SOAP requests with the recognizable placeholder 
"FUZZ_HERE" for each found location url).


## Example
    $ UPnPHunter.py 192.168.1.0/8 --all

    [+] UPnP location URL [1]:
    http://192.168.1.101:49001/urldesc.xml
    #------------------------------#
    [+] Soap request [1]:
    POST /upnp/control/WANIPConn1 HTTP/1.1
    SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"
    Host: 192.168.1.101:49155
    Content-Type: text/xml
    Content-Length: 437
        
    <?xml version="1.0"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <SOAP-ENV:Body>
        <m:DeletePortMapping xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">
            <NewProtocol>FUZZ_HERE</NewProtocol>
            <NewExternalPort>FUZZ_HERE</NewExternalPort>
            <NewRemoteHost>FUZZ_HERE</NewRemoteHost>
        </m:DeletePortMapping>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    [...]



# Author
- UPnP Hunter was developed by Maurizio Siddu


# GNU License
- Copyright (c) 2019 UPnP Hunter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

