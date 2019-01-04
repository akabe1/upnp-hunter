# UPnP Hunter
#
# Simple python script which could be useful to find active UPnP 
# services/devices in the specified target subnet and extract 
# the related SOAP requests.
#
# Copyright (C) 2019   Maurizio Siddu
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>



import socket
import select
import re
import sys
import os
import argparse
import xml.etree.ElementTree as ET
from urlparse import urlparse
import ipaddress, urllib2
import errno


# Proof of Sympathy ;-)
LOGO = """\
 ____ _____________     __________    ___ ___               __                
|    |   \______   \____\______   \  /   |   \ __ __  _____/  |_  ___________
|    |   /|     ___/    \|     ___/ /    ~    \  |  \/    \   __\/ __ \_  __ \\
|    |  / |    |  |   |  \    |     \    Y    /  |  /   |  \  | \  ___/|  | \/
|______/  |____|  |___|  /____|      \___|_  /|____/|___|  /__|  \_____>__|   
v1.0.0                 \/                  \/            \/                 
"""

# Define some global variables
SSDP_TIMEOUT = 2
ST_ALL = "ssdp:all"
ST_ROOTDEV = "upnp:rootdevice"
PLACEHOLDER = "FUZZ_HERE"
EXTENSION = ".txt"


class UPnPHunter():
    def __init__(self, upnp_locations, soap_reqs_dict, LAN_reqs_dict, WAN_reqs_dict):
        self.upnp_locations = []
        self.soap_reqs_dict = {}
        self.LAN_reqs_dict = {}
        self.WAN_reqs_dict = {}

    def getUPnPLocations(self):
        # Getter for upnp_location list
        return self.upnp_locations

    def getAllSOAPs(self):
        # Getter for upnp_location list
        return self.soap_reqs_dict

    def getLANSOAPs(self):
        # Getter for upnp_location list
        return self.LAN_reqs_dict

    def getWANSOAPs(self):
        # Getter for upnp_location list
        return self.WAN_reqs_dict



    def ssdpReqBuilder(self, ssdp_timeout, st_type):
        # Builder of the two ssdp msearch request types
        msearch_req = "M-SEARCH * HTTP/1.1\r\n" \
        "HOST: 239.255.255.250:1900\r\n" \
        "MAN: \"ssdp:discover\"\r\n" \
        "MX: {0}\r\n" \
        "ST: {1}\r\n" \
        "\r\n" \
        .format(ssdp_timeout, st_type)
        return msearch_req



    def sendMsearch(self, ssdp_req):
        # Send the ssdp request
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        buf_resp = []
        resp = ""
        while len(ssdp_req):
            # Blocking socket client until the request is completely sent
            try:
                sent = sock.sendto(ssdp_req.encode("ASCII"), ("239.255.255.250", 1900))
                ssdp_req = ssdp_req[sent:]
            except socket.error, exc:
                if exc.errno != errno.EAGAIN:
                    print("[E] Got error %s with socket when sending") % exc
                    sock.close()
                    raise exc
                print("[!] Blocking socket until ", len(ssdp_req), " is sent.")       
                select.select([], [sock], [])
                continue
        # Blocking socket until there are ssdp responses to be read or timeout is reached
        readable, __, __ = select.select([sock], [], [], SSDP_TIMEOUT)
        if not readable:
            # Timeout reached without receiving any ssdp response
            print("[!] Got timeout without receiving any ssdp response.")
        else:
            # Almost an ssdp response was received
            if readable[0]:
                try:
                    data = sock.recv(1024)
                    if data:
                        buf_resp.append(data.decode("ASCII"))
                except socket.error, exc:
                    print("[E] Got error %s with socket when receiving") % exc
                    sock.close()
                    raise exc
        # Assemblage of the ssdp response from received data chunks 
        resp = "".join(buf_resp)
        sock.close()
        return resp



    def discoverUpnpLocations(self):
        # Retrieve a list of UPnP location-urls via ssdp M-SEARCH broadcast request
        locations = set()
        location_regex = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)    
        # Use two possible type of ssdp requests 
        ssdp_requests = [self.ssdpReqBuilder(SSDP_TIMEOUT, ST_ALL), self.ssdpReqBuilder(SSDP_TIMEOUT, ST_ROOTDEV)]
        # First try with "Ssdp:All" request type
        print("[+] Start hunting with \"Ssdp:All\" ssdp request type")
        ssdp_response = self.sendMsearch(ssdp_requests[0])
        # Then try with the alternative "Root:Device" request type
        if not ssdp_response:
            print("[+] Retrying with \"Root:Device\" ssdp request type")
            ssdp_response = self.sendMsearch(ssdp_requests[1])
        # Extract location heaader information from ssdp response
        if ssdp_response:
            location_result = location_regex.search(ssdp_response.decode("ASCII"))
            if location_result and (location_result.group(1) in locations) == False:
                locations.add(location_result.group(1))
        else:
            print("[!] Unsucessfull hunt, none active UPnP service was found. Try with other target IPs")
            sys.exit(0)
        self.upnp_locations = list(locations)   



    def checkIPScope(self, found_locations, target_ip):
        # Create whitelist of in scope IPs and then check if found locations are in scope
        whitelist_ip = []
        scope_urls = []
        if target_ip.split("/")[1] == '32':
            # Subnet of single IP specified
            whitelist_ip.append(target_ip.split("/")[0])
        else:
            # Subnet of multiple IPs specified
            tmplist = list(ipaddress.ip_network(unicode(target_ip),False).hosts())
            for ip in tmplist: 
                whitelist_ip.append(str(ip))
        # Finally check if the found location IPs are in target scope
        if len(found_locations) > 0:
            for fl_url in found_locations:
                fl_ip =  urlparse(fl_url).netloc
                if fl_ip.split(":")[0] in str(whitelist_ip):
                    scope_urls.append(fl_url)
                    print("[+] Found valid location URL \"%s\"") % fl_url
                else:
                    print('[!] Discarded location URL \"%s\" because out of scope.') % fl_url
        return scope_urls

    

    def downloadXMLfiles(self, download_urls):
        # Download the specified xml files
        xml_files_dict = {}
        # First check if list of location urls is empty
        if download_urls:
            for d_url in download_urls:
                try:
                    # Get the xml files
                    download_req = urllib2.Request(d_url, None)
                    download_resp = urllib2.urlopen(download_req)
                    xml_files_dict[d_url] = download_resp
                except:
                    print("[!] Skipping, failed to retrieve the XML file: %s .") % d_url
                    continue
        return xml_files_dict



    def parseXMLfile(self, file_content, location_url):
        # Extract the juicy info from UPnP Description and SCDP xml files
        output_dict = {}
        arg_list = []
        # Parse the xml file
        tree = ET.parse(file_content)
        root_XML = tree.getroot()
        # Use the xml namespace 'xmlns="urn:schemas-upnp-org:device-1-0'
        ns = root_XML.tag.split('}')[0].strip('{')
        # Check if is a Description (with location_url) or SCDP file
        if location_url:
            # Parse the Description XML file to extract the info about Services
            # Build the base url element
            base_URL_elem = root_XML.findall(".//{"+ns+"}base_URL")
            if base_URL_elem:
                base_URL = base_URL_elem[0].text.rstrip('/')
            else:
                url = urlparse(location_url)
                base_URL = '%s://%s' % (url.scheme, url.netloc)
            # Extract service type, control url and scpd url 
            for serv in root_XML.findall(".//{"+ns+"}service"):
                service_type = (serv.find(".//{"+ns+"}serviceType")).text
                ctrl_URL = base_URL+(serv.find(".//{"+ns+"}controlURL")).text
                scpd_URL = base_URL+(serv.find(".//{"+ns+"}SCPDURL")).text
                # Aggregate the extracted info 
                output_dict[service_type] = [ctrl_URL, scpd_URL]
        else:
            # Parse the SCDP xml file to extract the info about Actions
            # Extract action info
            for act in root_XML.findall(".//{"+ns+"}action"):
                arg_name = []
                action_name = (act.find(".//{"+ns+"}name")).text
                # Determine if is a Get-action or not
                if action_name.startswith("Get"):
                    # Get-action found
                    if ( (act.find(".//{"+ns+"}argumentList/{"+ns+"}argument/{"+ns+"}direction")) is not None ) and \
                    ( (act.find(".//{"+ns+"}argumentList/{"+ns+"}argument/{"+ns+"}direction")).text == "in"):
                        # Get-action with input arguments
                        for argument_item in act.findall(".//{"+ns+"}argumentList/{"+ns+"}argument"):
                            if ( (argument_item.find(".//{"+ns+"}direction")) is not None ) and \
                            ( (argument_item.find(".//{"+ns+"}direction")).text == "in" ):
                                arg_name.append((argument_item.find(".//{"+ns+"}name").text))
                    else:
                        # Get-action without any input argument
                        arg_name.append("")
                else:
                    # Found a not Get-action
                    if (act.find(".//{"+ns+"}argumentList/{"+ns+"}argument/{"+ns+"}name")) is not None:
                        arg_list = act.findall(".//{"+ns+"}argumentList/{"+ns+"}argument/{"+ns+"}name")
                        for arg in arg_list:
                            arg_name.append(arg.text)
                    else:
                        # Not Get-action without any argument
                        arg_name.append("")
                # Aggregate the extracted info 
                output_dict[action_name] = arg_name
        return output_dict



    def soapReqBuilder(self, service_type, ctrl_URL, action_name, arg_list):
        # Build the soap requests for fuzzing purposes
        soap_enc = "http://schemas.xmlsoap.org/soap/encoding/"
        soap_env = "http://schemas.xmlsoap.org/soap/envelope/"
        service_ns = service_type
        soap_action = service_ns + "#" + action_name
        target_url = urlparse(ctrl_URL)
        soap_ip_port = target_url.netloc
        soap_path = target_url.path

        soap_body_top = "<?xml version=\"1.0\"?>\r\n" \
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{0}\" SOAP-ENV:encodingStyle=\"{1}\">\r\n" \
        "<SOAP-ENV:Body>\r\n" \
        "    <m:{2} xmlns:m=\"{3}\">\r\n" \
        .format(soap_env, soap_enc, action_name, service_ns)

        soap_body_tail = "    </m:{0}>\r\n" \
        "</SOAP-ENV:Body>\r\n" \
        "</SOAP-ENV:Envelope>" \
        .format(action_name)

        # Create the soap body fuzzable section with a recognizable placeholder
        sfuzz = []
        for arg_name in arg_list:
            if arg_name:
                sfuzz.append("        <{0}>{1}</{0}>".format(arg_name, PLACEHOLDER))
            else:
                # In case of Get-action or an action without arguments
                sfuzz.append("{0}".format(PLACEHOLDER))
        soap_body_fuzzable = "\r\n".join(sfuzz)

        # Assemblage of the soap body
        soap_body = soap_body_top + soap_body_fuzzable + "\r\n" + soap_body_tail

        # Final assemblage of the soap request
        soap_req = "POST {0} HTTP/1.1\r\n" \
        "SOAPAction: \"{1}\"\r\n" \
        "Host: {2}\r\n" \
        "Content-Type: text/xml\r\n" \
        "Content-Length: {3}\r\n" \
        "\r\n" \
        "{4}" \
        .format(soap_path, soap_action, soap_ip_port, len(soap_body), soap_body)
        '''
        EXAMPLE OF BUILT SOAP REQUEST:
        ------------------------------
        POST /upnp/control/WANIPConn1 HTTP/1.1
        SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"
        Host: 192.168.1.1:49155
        Content-Type: text/xml
        Content-Length: 437
        
        <?xml version="1.0"?>
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <SOAP-ENV:Body>
            <m:DeletePortMapping xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">
                <NewProtocol>TCP</NewProtocol>
                <NewExternalPort>7777</NewExternalPort>
                <NewRemoteHost></NewRemoteHost>
            </m:DeletePortMapping>
        </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
        '''        
        return soap_req



    def buildSOAPs(self, target_ip):
        # Retrieve all SOAP requests of the discovered UPnP services in scope
        scope_locations = self.checkIPScope(self.upnp_locations, target_ip)
        discovery_files_dict = self.downloadXMLfiles(scope_locations)
        for loc_url, loc_file in discovery_files_dict.iteritems():
            services_dict = self.parseXMLfile(loc_file, loc_url)
            all_soap_reqs, LAN_soap_reqs, WAN_soap_reqs = [], [], []
            skip_LAN = True
            skip_WAN = True
            for s_type in services_dict:
                scdp_list = []
                scdp_list.append(services_dict[s_type][1])
                print("[+] Downloading the SCDP file: \"%s\"") % services_dict[s_type][1]
                # Extract the juicy info from SCDP files
                scdp_dict = self.downloadXMLfiles(scdp_list)
                for scdp_file in scdp_dict.values():
                    action_dict = self.parseXMLfile(scdp_file, None)    
                # Build All the UPnP soap requests
                for ac_name in action_dict:
                    all_soap_reqs.append(self.soapReqBuilder(s_type, services_dict[s_type][0], ac_name, action_dict[ac_name]))    
                # Build only the LAN UPnP soap requests
                if "LANHostConfigManagement" in s_type:
                    skip_LAN = False
                    for ac_name in action_dict:
                        LAN_soap_reqs.append(self.soapReqBuilder(s_type, services_dict[s_type][0], ac_name, action_dict[ac_name]))
                # Build only the WAN UPnP soap requests
                if "WANIPConnection" in s_type or "WANPPPConnection" in s_type:
                    skip_WAN = False
                    for ac_name in action_dict:
                        WAN_soap_reqs.append(self.soapReqBuilder(s_type, services_dict[s_type][0], ac_name, action_dict[ac_name]))
            # Aggregate the built soap requests for each discovered location url
            if not skip_LAN:
                # Only LAN soap requests
                self.LAN_reqs_dict[loc_url] = LAN_soap_reqs
            if not skip_WAN:
                #  Only WAN soap requests
                self.WAN_reqs_dict[loc_url] = WAN_soap_reqs
            # All soap requests
            self.soap_reqs_dict[loc_url] = all_soap_reqs



    def printResults(self, input_dict):
        n_key = 0
        for key,values in input_dict.iteritems():
            n_key = n_key + 1
            print("[+] UPnP location URL [%s]:\n%s") % (n_key, key)
            print("#------------------------------#")
            n_value = 0
            for v in values:
                n_value = n_value+1
                print("[+] Soap request [%s]: \n%s\n") % (str(n_value), v)



    def saveFile(self, filename, input_dict):
        # Save the SOAP requests as text file in current folder
        print("[+] Saving resutls on file \"%s\" in current folder") % filename
        with open(filename,"wb") as fd:
            n_url = 0
            for url,requests in input_dict.iteritems():
                n_url = n_url + 1
                fd.write("UPnP location URL ["+str(n_url)+"]:\n\""+url+"\"")
                fd.write("\n#------------------------------------------------#")
                n_req = 0
                for req in requests:
                    n_req = n_req + 1
                    fd.write("\nSOAP request ["+str(n_req)+"]:\n")
                    fd.write(req+"\n")



def main():
    # Command line arguments parser with minimal input validion
    input_parser = argparse.ArgumentParser(description="Find UPnP services and build their SOAP requests")
    input_parser.add_argument("target_ip", type=str, help="Specify the target IP or subnet in CIDR notation (only IPv4 supported)")
    input_parser.add_argument("--all", "-a", action="store_true", help="Get all UPnP SOAP requests")
    input_parser.add_argument("--dangerous", "-d", action="store_true", help="Get only the dangerous UPnP SOAP requests (LANHostConfigManagement and WANIP/PPPConnection methods)")
    input_parser.add_argument("--output_file", "-o", type=str , help="Specify the file where to save the results")
    args = input_parser.parse_args()


    # Check if the specified target IP/subnet have a valid format
    if re.search(r'[^\d\.\/]', args.target_ip):
        print("[E] Exiting, inserted some invalid character for the target IP or subnet")
        sys.exit(-1)
    else:
        if not (re.match(r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|2[0-9]|1[0-9]|[0-9])$', args.target_ip)):
            print("[E] Exiting, invalid CIDR notation for the specified target IP or subnet")
            sys.exit(-1)

    # Check if the various result type options are correct
    if (not args.all and not args.dangerous):
        print("[!] You don't have specified any UPnP request type, default is \"ALL\"")
        args.all=True

    if (args.all and args.dangerous):
        print("[E] You must select only one type of UPnP request to build")
        input_parser.print_help()
        exit(-1)

    # Some checks on the specified output filename
    out_filename = ""
    if (args.output_file):
        if re.search(r'[^a-zA-Z0-9_\-\.\~]', args.output_file):
            print("[E] Exiting, specified an invalid filename")
            exit(-1)

        out_filename = args.output_file + EXTENSION
        if (os.path.exists(out_filename) or os.path.exists("lan_"+out_filename) or os.path.exists("wan_"+out_filename)):
            print("[E] Exiting, the specified filename is already present in current folder, cannot override it")
            sys.exit(-1)


    # Print the UPnP Hunter logo
    print(LOGO)
    # Instantiate the UPnPHunter object
    UH = UPnPHunter([],{},{},{})
    # Search UPnP location URLs via ssdp msearch request
    UH.discoverUpnpLocations()
    # Print all found location URLs (even those not in scope)
    for ul in UH.getUPnPLocations():
        print("[+] Found UPnP location URL: %s") % (ul)

    # Build the UPnP SOAP requests from discovered listening services/devices
    UH.buildSOAPs(args.target_ip)
    # Get all the SOAP requests
    if args.all:
        all_soaps = UH.getAllSOAPs()
        # Check the created UPnP soap requests
        if not all_soaps:
            # Something goes wrong, failed to build any soap request
            print("[E] Something goes wrong, some UPnP service was found but none UPnP SOAP request was created.")
        else:
            if out_filename:
                UH.saveFile(out_filename, all_soaps)
            else:
                print("[+] Printing all the UPnP SOAP requests for each in scope location URLs:")
                UH.printResults(all_soaps)

    # Get only the dangerous SOAP requests
    elif args.dangerous:
        lan_soaps = UH.getLANSOAPs()
        wan_soaps = UH.getWANSOAPs()
        # First check if any UPnP dangerous Soap request was built
        if not lan_soaps and not wan_soaps:
            # None dangerous soap request was found
            print("[+] Done, some UPnP service was found but none UPnP dangerous LAN and WAN methods were exposed")
        else:
            # Some dangerous LAN SOAP request were found
            if lan_soaps:
                print("[+] Some dangerous LANHostConfigManagement SOAP requests was found")
                if out_filename:
                    UH.saveFile("lan_"+out_filename, lan_soaps)
                else:
                    print("[+] Printing the LAN UPnP SOAP requests for each in scope location URLs:")
                    UH.printResults(lan_soaps)
 
            if wan_soaps:
                # Some dangerous WAN SOAP request were found
                print("[+] Some dangerous WANIP/PPPConnection SOAP requests was found")
                if out_filename:
                    UH.saveFile("wan_"+out_filename, wan_soaps)
                else:
                    print("[+] Printing the WAN UPnP SOAP requests for each in scope location URLs:")                
                    UH.printResults(wan_soaps)



if __name__ == "__main__":
    main()
