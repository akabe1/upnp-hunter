# UPnP Hunter
#
# Simple python script which could be useful to find active UPnP 
# services/devices in the specified target subnet and extract 
# the related SOAP, Subscribe and Presentation requests.
#
# Copyright (C) 2019 Maurizio Siddu
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
| | / | | | | \ | \ Y / | / | \ | \ ___ / | | \ /
|______/  |____|  |___|  /____|      \___|_  /|____/|___|  /__|  \_____>__|   
v2.0.0                 \/                  \/            \/                 
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
        self.Subs_reqs_dict = {}
        self.Pres_reqs_dict = {}



    def getUPnPLocations(self):
        # Getter for upnp_location list
        return self.upnp_locations

    def getAllSOAPs(self):
        # Getter for upnp_location list
        return self.soap_reqs_dict

    def getLANSOAPs (self):
        # Getter for upnp_location list
        return self.LAN_reqs_dict

    def getWANSOAPs(self):
        # Getter for upnp_location list
        return self.WAN_reqs_dict

    def getSubs(self):
        # Getter for upnp_location list
        return self.Subs_reqs_dict

    def getPres(self):
        # Getter for upnp_location list
        return self.Pres_reqs_dict



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
        # Send the ssdp request and retrieve response
        buf_resp = set()
        sock = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        # Sending ssdp requests
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
        # Retrieving ssdp responses
        num_resp = 0
        while sock:
            # Blocking socket until there are ssdp responses to be read or timeout is reached
            readable, __, __ = select.select([sock], [], [], SSDP_TIMEOUT)
            if not readable:
                # Timeout reached without receiving any ssdp response
                if num_resp == 0:
                	print("[!] Got timeout without receiving any ssdp response.")
                break
            else:
            	num_resp = num_resp + 1
                # Almost an ssdp response was received
                if readable[0]:
                    try:
                   		data = sock.recv(1024)
                   		if data:
                 			buf_resp.add(data.decode('ASCII'))
                    except socket.error, exc:
                        print("[E] Got error %s with socket when receiving") % exc
                        sock.close()
                        raise exc
        sock.close()
        # Assemblage of the ssdp response from received data chunks
        resp = list(buf_resp)
        return resp



    def discoverUpnpLocations(self):
        # Retrieve a list of UPnP location-urls via ssdp M-SEARCH broadcast request
        locations = set()
        location_regex = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)    
        # Use two possible type of ssdp requests 
        ssdp_requests = [self.ssdpReqBuilder(SSDP_TIMEOUT, ST_ALL), self.ssdpReqBuilder(SSDP_TIMEOUT, ST_ROOTDEV)]
        # First try with "Ssdp:All" request type
        print("[+] Start hunting with \"Ssdp:All\" ssdp request type")
        ssdp_responses = self.sendMsearch(ssdp_requests[0])
        # Then try with the alternative "Root:Device" request type
        if not ssdp_responses:
            print("[+] Retrying with \"Root:Device\" ssdp request type")
            ssdp_responses = self.sendMsearch(ssdp_requests[1])
        # Extract location heaader information from ssdp response
        if ssdp_responses:
            for ssdp_resp in ssdp_responses:
                location_result = location_regex.search(ssdp_resp.decode("ASCII"))
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
                fl_ip = urlparse (fl_url) .netloc
                if fl_ip.split(":")[0] in whitelist_ip:
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
                    # Extract the response body
                    if download_resp and download_resp.code == 200 and download_resp.msg:
                        print("[+] Successfully downloaded xml file \"%s\" ") % d_url
                        read_resp = download_resp.read()
                        xml_files_dict[d_url] = read_resp
                except:
                    print("[!] Skipping, failed to retrieve the XML file: %s .") % d_url
                    continue
        return xml_files_dict



    def buildURL(self, url, base_url):
        if not url.startswith("http"):
            if url.startswith("/"):
                url = base_url + url
            else:
                url = base_url + "/" + url
        return url



    def parseXMLfile(self, file_content, location_url, isPresentation):
        # Extract the juicy info from UPnP Description and SCDP xml files
        output_dict = {}
        arg_list = []
        ctrl_URL, scpd_URL, subs_URL, pres_URL = None, None, None, None
        # Parse the xml file content
        #file_content = file_content.replace("\t", "")
        #file_content = file_content.replace(" ", "")
        root_XML = ET.fromstring(file_content)
        # Use the xml namespace 'xmlns="urn:schemas-upnp-org:device-1-0'
        ns = root_XML.tag.split('}')[0].strip('{')
        if ns == 'root':
            print("[!] Error the UPnP Discovery file has not xml namespace, exiting.")
            sys.exit(0)
        # Check if is a Description (with location_url) or SCDP file
        if location_url:
            # Parse the Description XML file to extract the info about Services
            # Build the base url element
            base_URL_elem = root_XML.findall(".//{"+ns+"}URLBase")
            if base_URL_elem:
                base_URL = base_URL_elem[0].text.rstrip('/')
            else:
                url = urlparse (location_url)
                base_URL = '%s://%s' % (url.scheme, url.netloc)
            # Run here when searching presentation url in Description file
            if isPresentation:
                # Extract presentationURL
                pres_URL_elem = (root_XML.findall(".//{"+ns+"}presentationURL"))
                if pres_URL_elem:
                    pres_URL = pres_URL_elem[0].text.rstrip('/')
                    pres_URL = self.buildURL(pres_URL, base_URL)
                # Aggregate the extracted info
                output_dict['pres_upnphunter'] = [None, None, None, pres_URL]
            # Run here when searching for services in Description file
            else:
                # Extract service type, control url, scpd url and subscribe url 
                for serv in root_XML.findall(".//{"+ns+"}service"):
                    service_type = (serv.find(".//{"+ns+"}serviceType")).text
                    ctrl_URL = (serv.find(".//{"+ns+"}controlURL")).text
                    ctrl_URL = self.buildURL(ctrl_URL, base_URL)
                    scpd_URL = (serv.find(".//{"+ns+"}SCPDURL")).text
                    scpd_URL = self.buildURL(scpd_URL, base_URL)
                    subs_URL = (serv.find(".//{"+ns+"}eventSubURL")).text
                    subs_URL = self.buildURL(subs_URL, base_URL)
                    # Aggregate the extracted info 
                    output_dict[service_type] = [ctrl_URL, scpd_URL, subs_URL, None]
        # Run here when parsing SCDP files                    
        else:
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
            services_dict = self.parseXMLfile(loc_file, loc_url, False)
            all_soap_reqs, LAN_soap_reqs, WAN_soap_reqs = [], [], []
            skip_LAN = True
            skip_WAN = True
            for s_type in services_dict:
                # Build the soap requests
                scdp_list = []
                if s_type != 'pres_upnphunter':
                    scdp_list.append(services_dict[s_type][1])
                print("[+] Downloading the SCDP file: \"%s\"") % services_dict[s_type][1]
                # Extract the juicy info from SCDP files
                scdp_dict = self.downloadXMLfiles(scdp_list)
                if not scdp_dict:
                    print("[!] Warning, no UPnP service retrieved for %s" % "".join(scdp_url for scdp_url in scdp_list))
                    continue
                for scdp_file in scdp_dict.values():
                    action_dict = self.parseXMLfile(scdp_file, None, False)    
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
                self.WAN_reqs_dict [loc_url] = WAN_soap_reqs
            # All soap requests
            self.soap_reqs_dict[loc_url] = all_soap_reqs





    def subscribeReqBuilder(self, subs_URL):
        # Build the subscribe requests for testing purposes
        target_url = urlparse(subs_URL)
        subscribe_ip_port = target_url.netloc
        subscribe_path = target_url.path
        # Callback IP and port must be manually specified on burp repeater
        callback_ip_port = "http://"+"YOUR_LISTENING_IP:YOUR_LISTENING_PORT"
        # Final assemblage of the subscribe request
        subscribe_req = "SUBSCRIBE {0} HTTP/1.1\r\n" \
        "Host: {1}\r\n" \
        "User-Agent: unix/5.1 UPnP/1.1 BHunter/2.0\r\n" \
        "Callback: <{2}>\r\n" \
        "NT: upnp:event\r\n" \
        "Timeout: Second-300\r\n" \
        "\r\n" \
        .format(subscribe_path, subscribe_ip_port, callback_ip_port)
        '''
        EXAMPLE OF BUILT SUBSCRIBE REQUEST:
        -----------------------------------
        SUBSCRIBE /upnp/event/WiFiSetup1 HTTP/1.1
        HOST: 192.168.1.1:49155
        USER-AGENT:  unix/5.1 UPnP/1.1 BHunter/2.0
        CALLBACK: <http://192.168.1.42:4444>
        NT: upnp:event
        TIMEOUT: Second-300
        '''        
        return subscribe_req




    def buildSubscribes(self, target_ip):
        subs_req_dict = {}
        scope_locations = self.checkIPScope(self.upnp_locations, target_ip)
        discovery_files_dict = self.downloadXMLfiles(scope_locations)
        for loc_url, loc_file in discovery_files_dict.iteritems():
            services_dict = self.parseXMLfile(loc_file, loc_url, False)
            subs_reqs = []
            for s_type in services_dict:
                # Build All the UPnP subscribe requests
                if s_type != 'pres_upnphunter':
                    if services_dict[s_type][2]:
                        subs_reqs.append(self.subscribeReqBuilder(services_dict[s_type][2]))
            if subs_reqs:
                self.Subs_reqs_dict[loc_url] = subs_reqs



    def presentationReqBuilder(self, pres_URL):
        # Build the presentation requests for testing purposes
        target_url = urlparse(pres_URL)
        presentation_ip_port = target_url.netloc
        presentation_path = target_url.path
        if not presentation_path:
            presentation_path = "/"
        # Final assemblage of the subscribe request
        presentation_req = "GET {0} HTTP/1.1\r\n" \
        "Host: {1}\r\n" \
        "User-Agent: unix/5.1 UPnP/1.1 BHunter/2.0\r\n" \
        "\r\n" \
        .format(presentation_path, presentation_ip_port)
        '''
        EXAMPLE OF BUILT PRESENTATION REQUEST:
        -----------------------------------
        GET /pres_page.html HTTP/1.1
        HOST: 192.168.1.1:49155
        USER-AGENT:  unix/5.1 UPnP/1.1 BHunter/2.0
        '''        
        return presentation_req



    def buildPresentations(self, target_ip):
        pres_req_dict = {}
        scope_locations = self.checkIPScope(self.upnp_locations, target_ip)
        discovery_files_dict = self.downloadXMLfiles(scope_locations)
        for loc_url, loc_file in discovery_files_dict.iteritems():
            services_dict = self.parseXMLfile(loc_file, loc_url, True)
            pres_reqs = []
            # Build the UPnP presentation request
            if services_dict["pres_upnphunter"] and services_dict["pres_upnphunter"][3]:
                pres_reqs.append(self.presentationReqBuilder(services_dict["pres_upnphunter"][3]))
            if pres_reqs:
                self.Pres_reqs_dict[loc_url] = pres_reqs



    def printResults(self, input_dict):
        n_key = 0
        for key,values in input_dict.iteritems():
            n_key = n_key + 1
            print("[+] UPnP location URL [%s]: %s\n") % (n_key, key)
            n_value = 0
            for v in values:
                n_value = n_value+1
                print("[+] UPnP request [%s]: \n%s\n") % (str(n_value), v)
            print("[------------ End UPnP requests for location URL [%s] [%s] -----------]\n") % (n_key, key)



    def saveFile(self, filename, input_dict):
        # Save the SOAP requests as text file in current folder
        print("[+] Saving resutls on file \"%s\" in current folder") % filename
        with open(filename,"wb") as fd:
            n_url = 0
            for url,requests in input_dict.iteritems():
                n_url = n_url + 1
                fd.write("UPnP location URL ["+str(n_url)+"]:\n\""+url+"\"\n")
                fd.write("\n")
                n_req = 0
                for req in requests:
                    n_req = n_req + 1
                    fd.write("\nUPnP request ["+str(n_req)+"]:\n")
                fd.write("[------------- End UPnP requests for location URL ["+str(n_url)+"] ---------------]\n\n")



def main():
    # Command line arguments parser with minimal input validion
    input_parser = argparse.ArgumentParser(description="Find UPnP services and build their SOAP requests")
    input_parser.add_argument("target_ip", type=str, help="Specify the target IP or subnet in CIDR notation (only IPv4 supported)")
    input_parser.add_argument("--all", "-a", action="store_true", help="Get all UPnP SOAP requests")
    input_parser.add_argument("--igd", "-i", action="store_true", help="Get only the IGD SOAP requests (LANHostConfigManagement and WANIP/PPPConnection methods)")
    input_parser.add_argument("--subs", "-s", action="store_true", help="Get all UPnP SUbscribe requests")
    input_parser.add_argument("--pres", "-p", action="store_true", help="Get all UPnP Presentation requests")
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
    if (not args.all and not args.igd and not args.subs and not args.pres):
        print("[!] You don't have specified any UPnP request type, default is \"ALL Soaps\"")
        args.all=True

    if (args.all and args.igd and args.subs and args.pres):
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
    UH.buildSubscribes(args.target_ip)
    UH.buildPresentations(args.target_ip)
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

    # Get only the IGD SOAP requests
    elif args.igd:
        lan_soaps = UH.getLANSOAPs()
        wan_soaps = UH.getWANSOAPs()
        # First check if any UPnP IGD Soap request was built
        if not lan_soaps and not wan_soaps:
            # None igd soap request was found
            print("[+] Done, some UPnP service was found but none UPnP IGD methods were exposed")
        else:
            # Check if some IGD LAN SOAP request were found
            if lan_soaps:
                print("[+] Some IGD LANHostConfigManagement SOAP request was found")
                if out_filename:
                    UH.saveFile("lan_"+out_filename, lan_soaps)
                else:
                    print("[+] Printing the LAN UPnP SOAP requests for each in scope location URLs:")
                    UH.printResults(lan_soaps)
                    print("[------------- End LAN UPnP SOAP requests -------------------]")
            # Check if some IGD WAN SOAP request were found
            if wan_soaps:
                print("[+] Some IGD WANIP/PPPConnection SOAP request was found")
                if out_filename:
                    UH.saveFile("wan_"+out_filename, wan_soaps)
                else:
                    print("[+] Printing the WAN UPnP SOAP requests for each in scope location URLs:")                
                    UH.printResults(wan_soaps)
                    print("[------------- End WAN UPnP SOAP requests -------------------]")

    # Get only the Subscribe requests                    
    elif args.subs:
        all_subs = UH.getSubs()
        # Check the created UPnP Subscribe requests
        if not all_subs:
            # Something goes wrong, failed to build any subscribe request
            print("[E] Something goes wrong, some UPnP service was found but none UPnP Subscribe request was created.")
        else:
            if out_filename:
                UH.saveFile(out_filename, all_subs)
            else:
                print("[+] Printing all the UPnP Subscribe requests for each in scope location URLs:")
                UH.printResults(all_subs)

    # Get only the Presentation requests   
    elif args.pres:
        all_pres = UH.getPres()
        # Check the created UPnP Presentation requests
        if not all_pres:
            # Something goes wrong, failed to build any presentation request
            print("[E] Something goes wrong, some UPnP service was found but none UPnP Presentation request was created.")
        else:
            if out_filename:
                UH.saveFile(out_filename, all_pres)
            else:
                print("[+] Printing all the UPnP Presentation requests for each in scope location URLs:")
                UH.printResults(all_pres)




if __name__ == "__main__":
    main()
