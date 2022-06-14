## Python script to bulk add Remote Networks
## by Marc Gollop
## Configuration file 'config.yaml', required elements are:
## clientID, clientSecret and TtnantID
## Name of the csvFile file, the shared key (PSK)
## IKEVersion of IKE required - currentlly we configure both and put down ikev2 preferred, but this add this feature later
## PassiveMode - To select if the IKE Passive Mode flag is selected

## The csv file must have the following header line 
##
## Name,Compute_Region,SPN,Dual_Tunnel,Tunnel_IP1,Tunnel_IP2,Peer_Type,Local_Peer1,Remote_Peer1,Local_Peer2,Remote_Peer2,Monitor_IP1,Monitor_IP2,BGP_AS,BGP_Local1,BGP_Local2,BGP_Peer1,BGP_Peer2,Static_Route
##
## Columns that are empty are not configured
##  If Tunnel_IPx is empty, then the tunnel will be set to dynamic - This will require a Peer_Type and Remote_Peer at a minimum
##  Peer_Type can be empty (no peering defined), "ipaddr" "keyid" "fqdn" "ufqdn" - aka email
## If Monitor_IPx is empty, then the monitoring will not be turned on
## If you want to add more than 1 static route, you need use : as the delimeter between routes. If you leave out the Static_Route column - you must define BGP
## Only the BGP_AS is required
## NOTE: there is no error checking of the IP addresses, etc. An Error will stop the script from working

import os
import sys
import requests
import yaml
import csv
import json
import time
import argparse
import logging
logger = logging.getLogger("rn-bulk-load")

# preload the large tables
locdict = {}
spndict = {}
rndict = {}
ipsecdict = {}
ikedict = {}
csvdict = {}
confdict = {}
client_id = ""
client_secret = ""
tenant_id = ""
ike_version = ""
passive_mode = ""
shared_key = ""
csv_file = ""

# default URL's and authentication server for API acces
base_api_url = "https://api.sase.paloaltonetworks.com/sse/config/v1/"
auth_server_url = "https://auth.apps.paloaltonetworks.com:443/am/oauth2/access_token"
# Currently only supporting the standard IKE and IPSec Crypto's. If you have custom one's then change these to what suits
IPsec_Crypto = "PaloAlto-Networks-IPSec-Crypto"
IKE_Crypto = "PaloAlto-Networks-IKE-Crypto"
IKE_template = {
	"name": "",
	"authentication_key": "",
	"peer_id": {
		"type": "fqdn",
		"id": ""
	},
	"local_id": {
		"type": "fqdn",
		"id": ""
	},
	"protocol": {
		"ikev1": {
			"ike_crypto_profile": "",
			"dpd": {
				"enable": True
			}
		},
		"ikev2": {
			"ike_crypto_profile": "",
			"dpd": {
				"enable": True
			}
		},
		"version": "ikev2-preferred"
	},
	"protocol_common": {
		"nat_traversal": {
			"enable": True
		},
		"passive_mode": True,
		"fragmentation": {
			"enable": False
		}
	},
	"peer_address": {
	}
}
IPSec_template = {
    "name": "",
    "auto_key" : {
        "ike_gateway" : [
            {
                "name": ""
            }
        ],
        "ipsec_crypto_profile": ""
    },
    "tunnel_monitor" : {
        "enable": True,
        "destination_ip": ""
    }
}
RN_template = {
  "name": "",
  "ipsec_tunnel": "",
  "license_type": "FWAAS-AGGREGATE",
  "region": "",
  "subnets": [ "" ],
  "spn_name": "",
  "ecmp_load_balancing": "disable"
}

def get_new_token():
    api_token_response = requests.post(auth_server_url,
        data={
              'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': tenant_id
        })

    if api_token_response.status_code !=200:
        logger.error("Failed to obtain token from the OAuth 2.0 server")
        sys.exit(1)
    logger.info("Successfuly obtained a new token")
    tokens = json.loads(api_token_response.text)
    return tokens['access_token']

## Perform a get, if the token has expired, reapply for the token
def get_api(token, url):
    logger.debug("Called Get API: %s",url)
    api_call_headers = {'Authorization': 'Bearer ' + token}
    api_call_response = requests.get(url, headers=api_call_headers)
    logger.debug("Get_API response code %s",api_call_response.status_code )
    if	api_call_response.status_code == 401:
        token = get_new_token()
        api_call_response = requests.get(url, headers=api_call_headers)
    if	api_call_response.status_code == 404:
        return('{"data":[]}')
    else:
        return(api_call_response.text)

## Perform a post, if the token has expired, reapply for the token
def post_api(token, url, data):
    logger.debug("Called Post API: %s",url)
    logger.debug(data)
    api_call_headers = {'Authorization': 'Bearer ' + token}
    api_call_response = requests.post(url, json=data, headers=api_call_headers)
    logger.debug("Post_API response code %s",api_call_response.status_code )
    if	api_call_response.status_code == 401:
        token = get_new_token()
        api_call_response = requests.post(url, json=data, headers=api_call_headers)
    if	api_call_response.status_code == 404:
        return('{"data":[]}')
    else:
        return(api_call_response.text)

## Perform a put, if the token has expired, reapply for the token
def put_api(token, url, data):
    logger.debug("Called Put API: %s",url)
    logger.debug(data)
    api_call_headers = {'Authorization': 'Bearer ' + token}
    api_call_response = requests.put(url,json=data, headers=api_call_headers)
    logger.debug("Put_API response code %s",api_call_response.status_code )
    if	api_call_response.status_code == 401:
        token = get_new_token()
        api_call_response = requests.put(url, json=data, headers=api_call_headers)
    if	api_call_response.status_code == 404:
        return('{"data":[]}')
    else:
        return(api_call_response.text)

## Perform a put, if the token has expired, reapply for the token
def delete_api(token, url):
    logger.debug("Called Delete API: %s",url)
    api_call_headers = {'Authorization': 'Bearer ' + token}
    api_call_response = requests.delete(url, headers=api_call_headers)
    logger.debug("Delete_API response code %s",api_call_response.status_code )
    if	api_call_response.status_code == 401:
        token = get_new_token()
        api_call_response = requests.delete(url, headers=api_call_headers)
    if	api_call_response.status_code == 404:
        return('{"data":[]}')
    else:
        return(api_call_response.text)

# check that validity of the Compute Region and SPN are correct. Also check if the RN/IPSec/IKE's exist
def check_rn(csvrow):
    ### Check that the Compute Regions are correct.
    found = False
    for location in locdict:
        if location['display'] == csvrow["Compute_Region"]:
            csvrow["aggregate_region"] = location['aggregate_region']
            csvrow["region"] = location['region']
            found = True
            break
    if not found:
        loggger.error("%s, %s is not valid", csvrow['Name'], csvrow["Compute_Region"])
        raise SystemExit(1)
    ### Check is the SPN Exists. If it does not exist then it needs to be added manually. 
    found = False
    for spn in spndict['data']:
        if spn['name'] == csvrow["aggregate_region"]:
            if csvrow['SPN'] in spn['spn_name_list']:
                found = True
                break
    if not found:
        logger.error("%s in %s with SPN %s is not valid",csvrow['Name'],csvrow["Compute_Region"], csvrow['SPN'])
        raise SystemExit(1)
    ### Check if the Remote Networks exist. Flag that they need Editting vs creation if they do exist.
    csvrow['NewRN'] = True
    for rn in rndict['data']:
        if csvrow['Name'] in rn['name']:
                csvrow['NewRN'] = False
                csvrow['RN_ID'] = rn['id']
                break
    ### Check if the IPSec Tunnels exist. Flag that they need Editting vs creation if they do exist.
    csvrow['NewIPSec1'] = True
    csvrow['NewIPSec2'] = True
    for ipsec in ipsecdict['data']:
        if csvrow['IPSec_Name1'] in ipsec['name']:
                csvrow['NewIPSec1'] = False
                csvrow['IPSec1_ID'] =ipsec['id']
        if csvrow['IPSec_Name2']  in ipsec['name']:
                csvrow['NewIPSec2'] = False
                csvrow['IPSec2_ID'] =ipsec['id']
    ### Check if the IKE Tunnels exist. Flag that they need Editting vs creation if they do exist.
    csvrow['NewIKE1'] = True
    csvrow['NewIKE2'] = True
    for ike in ikedict['data']:
        if csvrow['IKE_Name1']  in ike['name']:
                csvrow['NewIKE1'] = False
                csvrow['IKE1_ID'] =ike['id']
        if csvrow['IKE_Name2'] in ike['name']:
                csvrow['NewIKE2'] = False
                csvrow['IKE2_ID'] =ike['id']
    return(csvrow)

def ike_setup(name, psk, peer_type,local_id,peer_id,crypto,mode,peer_ip):
    ike_data = IKE_template
    ike_data['name'] = name
    ike_data['authentication_key'] = psk
    ike_data['peer_id']['type'] = peer_type
    ike_data['peer_id']['id'] = peer_id
    ike_data['local_id']['type'] = peer_type
    ike_data['local_id']['id'] = local_id
    ike_data['protocol']['ikev1']['ike_crypto_profile'] = crypto
    ike_data['protocol']['ikev2']['ike_crypto_profile'] = crypto
    ike_data['protocol_common']['passive_mode'] = mode
    if peer_ip == "":
        ike_data['peer_address']['dynamic'] = {}
    else:
        ike_data['peer_address']['ip'] = peer_ip
    return ike_data


def ipsec_setup(name, ike_name,crypto,monitor_ip):
    ipsec_data= IPSec_template
    ipsec_data['name'] = name
    ipsec_data['auto_key']['ike_gateway'][0]['name'] = ike_name
    ipsec_data['auto_key']['ipsec_crypto_profile'] = crypto
    if monitor_ip == "":
        ipsec_data['tunnel_monitor']['enable'] = False
    else:  
        ipsec_data['tunnel_monitor']['enable'] = True
        ipsec_data['tunnel_monitor']['destination_ip'] = monitor_ip
    return ipsec_data

def rn_setup(name, dual_tunnel, ipsec_name1, ipsec_name2, region, spn, bgp_as,bgp_l1,bgp_l2,bgp_p1,bgp_p2,subnets):
    rn_data= RN_template
    rn_data['name'] = name
    rn_data['ipsec_tunnel'] = ipsec_name1
    rn_data['region'] = region
    rn_data['subnets'] = subnets
    rn_data['spn_name'] = spn
    if dual_tunnel == "True":
        rn_data['secondary_ipsec_tunnel']= ipsec_name2
    if bgp_as != "":
        rn_data['protocol'] = {'bgp' : {}}
        rn_data['protocol']['bgp']['enable'] = True
        rn_data['protocol']['bgp']['peer_as'] = bgp_as
        if bgp_p1 == '':
            print("Oh dear")
        else:
            rn_data['protocol']['bgp_peer'] = {} 
            rn_data['protocol']['bgp']['peer_ip_address'] = bgp_p1
            rn_data['protocol']['bgp_peer']['peer_ip_address'] = bgp_p1
            if bgp_l1 != '':
                rn_data['protocol']['bgp']['local_ip_address'] = bgp_l1
                rn_data['protocol']['bgp_peer']['local_ip_address'] = bgp_l1
            if bgp_l2 != '':
                rn_data['protocol']['bgp_peer']['local_ip_address'] = bgp_l2
            if bgp_p2 != '':
                rn_data['protocol']['bgp_peer']['peer_ip_address'] = bgp_p2
                rn_data['protocol']['bgp_peer']['same-as-primary'] = 'no' 
    return rn_data

# This function loads the Yaml config. Work that needs to be done is to check that all the required fields are there
def load_config():
    global client_id
    global client_secret
    global tenant_id
    global ike_version
    global passive_mode
    global shared_key
    global csv_file
    
    logger.info("Load Config.yaml file")
    try:
        with open("config.yaml", "rt") as confrawfile:
            conffile = confrawfile.read()
    except Exception:
        logger.error("Can't read config.yaml file")
        raise SystemExit(1)
    confdict = yaml.load(conffile, Loader=yaml.FullLoader)
    client_id = confdict.get("clientID")
    client_secret = confdict.get("clientSecret")
    tenant_id = confdict.get("tenantID")
    if tenant_id == None:
        if client_id.find('@') >= 0:
            tenant_id = "tsg_id:" + client_id.split("@",1)[1].split(".",1)[0]
            logger.error("Tenant ID not defined derived tenant_id %s from Email")
        else:
            logger.error("Tenant ID not defined and Client ID is not an Email")
            raise SystemExit(1)            
    ike_version = confdict.get("IKEversion")
    passive_mode = confdict.get("PassiveMode")
    if passive_mode == None:
        passive_mode = False
    elif passive_mode != True:
        passive_mode = False
    shared_key = confdict.get("PSK")
    csv_file = confdict.get("csvFile")
    if client_id == None or client_secret == None:
        logger.error("Missing required parameter. Current parameters are")
        logger.error("client_id: %s", client_id)
        logger.error("client_secret: %s", client_secret)
        logger.error("tenant_id: %s", tenant_id)
        raise SystemExit(1)
    logger.debug("client_id: %s", client_id)
    logger.debug("client_secret: %s", client_secret)
    logger.debug("tenant_id: %s", tenant_id)
    logger.debug("ike_version: %s", ike_version)
    logger.debug("passive_mode: %s", passive_mode)
    if shared_key == None:
        logger.warning("No Shared Key Defined")
    logger.debug("shared_key: %s", shared_key)
    logger.debug("csv_file: %s", csv_file)

# CSV Layout = Name,Compute_Region,SPN,Dual_Tunnel,Tunnel_IP1,Tunnel_IP2,Peer_Type,Local_Peer1,Remote_Peer1,Local_Peer2,Remote_Peer2,Monitor_IP1,Monitor_IP2,BGP_AS,BGP_Local1,BGP_Local2,BGP_Peer1,BGP_Peer2,Static_Route
# This function will check that the header is correct 
def validate_csv(rawfile):
    # Check if all the fieldnames are there
    logger.info("Checking that all the columns are there")
    csvd = csv.DictReader(rawfile.splitlines())
    if csvd.fieldnames.count("Name") != 1 or csvd.fieldnames.count("Compute_Region") != 1 or \
            csvd.fieldnames.count("SPN") != 1 or csvd.fieldnames.count("Dual_Tunnel") != 1 or \
            csvd.fieldnames.count("Tunnel_IP1") != 1 or csvd.fieldnames.count("Tunnel_IP2") != 1 or \
            csvd.fieldnames.count("Local_Peer1") != 1 or csvd.fieldnames.count("Remote_Peer1") != 1 or \
            csvd.fieldnames.count("Local_Peer2") != 1 or csvd.fieldnames.count("Remote_Peer2") != 1 or \
            csvd.fieldnames.count("Monitor_IP1") != 1 or csvd.fieldnames.count("Monitor_IP2") != 1 or \
            csvd.fieldnames.count("BGP_Local1") != 1 or csvd.fieldnames.count("BGP_Local2") != 1 or \
            csvd.fieldnames.count("BGP_Peer1") != 1 or csvd.fieldnames.count("BGP_Peer2") != 1 or \
            csvd.fieldnames.count("Peer_Type") != 1 or csvd.fieldnames.count("BGP_AS") != 1 or \
            csvd.fieldnames.count("Static_Route") != 1:
                logger.error("Incorrect CSV keys")
                return False           
    return True

# This function loads the CSV. If the CSV cannot load it will stop. Work that needs to be done is to check that all the fields are there
def load_csv():
    global csvdict

    logger.info("Loading CSV File : %s",csv_file)
    try:
        with open(csv_file, newline='') as csvrawfile:
            csvfile = csvrawfile.read()
    except Exception:
        logger.error("Can't read " + csv_file + "file")
        raise SystemExit(1)
    # Get rid of n/a and N/A
    csvfile = csvfile.replace(",N/A", ",")
    csvfile = csvfile.replace(",n/a", ",")
    if not validate_csv(csvfile):
        logger.error("Invalid Columns in " + csv_file + "file")
        raise SystemExit(1)
    # Read the differnt RN's you want to create    
    csvdict = csv.DictReader(csvfile.splitlines())
    logger.debug("Imported CSV")

#This function loads the locations, SPNs, RN's. IPSec Tunnels and IKE Gateways. Work that needs to be done is to confirm that there are not more than 200, and if there are to load the next lot
def load_current_state(token):
    global locdict
    global spndict
    global rndict
    global ipsecdict
    global ikedict

    logger.info("Loading the current state from Prisma Access API")
    print(".")
    # learn the locations
    url = base_api_url + "locations"
    locdict = json.loads(get_api(token,url))
    if "_errors" in locdict:
        logger.error(locdict)
        raise SystemExit(1)
    logger.info("Loaded Locations")
    print(".")
   # learn the SPN's
    url = base_api_url + "bandwidth-allocations"
    spndict = json.loads(get_api(token,url))
    if "_errors" in spndict:
        logger.error(spndict)
        raise SystemExit(1)
    logger.info("Loaded SPNs")
    logger.debug(spndict)
    print(".")
  # learn the Existing RN's
    url = base_api_url + "remote-networks?folder=Remote%20Networks"
    rndict = json.loads(get_api(token,url))
    if "_errors" in rndict:
        logger.error(rndict)
        raise SystemExit(1)
    logger.info("Loaded Remote Networks")
    logger.debug(rndict)  
    print(".")
  # learn the Existing IPSEc Tunnels
    url = base_api_url + "ipsec-tunnels?folder=Remote%20Networks"
    ipsecdict = json.loads(get_api(token,url))
    if "_errors" in ipsecdict:
        logger.error(ipsecdict)
        raise SystemExit(1)
    logger.info("Loaded IPSec Tunnels")
    logger.debug(ipsecdict)  
    print(".")
  # learn the IKE Tunnels
    url = base_api_url + "ike-gateways?folder=Remote%20Networks"
    ikedict = json.loads(get_api(token,url))
    if "_errors" in ikedict:
        logger.error(ikedict)
        raise SystemExit(1)
    logger.info("Loaded IKE Gateways")
    logger.debug(ikedict)  
    print(".")

def commit_config():
    commit_data = {
        "folders": [ 
            "Remote Networks" 
            ]
    }
    url = base_api_url + "config-versions/candidate:push"
    response = json.loads(post_api(token, url, commit_data))
    if "_errors" in response:
        logger.error(response)
        raise SystemExit(1)

def create_config(csvrow):
    ## Create/Edit the 1st IKE Gateway
    ike_data = ike_setup(csvrow['IKE_Name1'], shared_key, csvrow['Peer_Type'], csvrow['Local_Peer1'],csvrow['Remote_Peer1'],IKE_Crypto,passive_mode,csvrow['Tunnel_IP1'])
    logger.info("IKE1 - " + ("Edit ","Create ")[csvrow['NewIKE1']] + csvrow['IKE_Name1'] )
    logger.debug(ike_data)
    if csvrow['NewIKE1']:
        url = base_api_url + "ike-gateways?folder=Remote%20Networks"
        response = json.loads(post_api(token, url, ike_data))
    else: 
        url = base_api_url + "ike-gateways/" + csvrow['IKE1_ID'] + "?folder=Remote%20Networks"
        response = json.loads(put_api(token, url, ike_data))
    if "_errors" in response:
        logger.error(response)
        raise SystemExit(1)

    ## Create/Edit the 1st IPSec Tunnel
    ipsec_data = ipsec_setup(csvrow['IPSec_Name1'],csvrow['IKE_Name1'],IPsec_Crypto,csvrow['Monitor_IP1'])
    logger.info("IPSec1 - " + ("Edit ","Create ")[csvrow['NewIPSec1']] + csvrow['IPSec_Name1']  )
    logger.debug(ipsec_data)
    if csvrow['NewIPSec1']:
        url = base_api_url + "ipsec-tunnels?folder=Remote%20Networks"
        response = json.loads(post_api(token, url, ipsec_data))
    else: 
        url = base_api_url + "ipsec-tunnels/" + csvrow['IPSec1_ID'] + "?folder=Remote%20Networks"
        response = json.loads(put_api(token, url, ipsec_data))
    if "_errors" in response:
        logger.error(response)
        raise SystemExit(1)
    ## Allowed fields in Dual Tunnel are YES or TRUE, anything else we assume it is only 1 tunnel
    if csvrow['Dual_Tunnel'].upper() == "YES" or csvrow['Dual_Tunnel'].upper() == "TRUE":
        csvrow['Dual_Tunnel'] == "True"
    elif csvrow['Dual_Tunnel'].upper() != "NO" and csvrow['Dual_Tunnel'].upper() != "FALSE":
        csvrow['Dual_Tunnel'] == "False"
        logger.warning("Dual Tunnel was not set for Yes/No or True/False, defaulted to False")
    
    if csvrow['Dual_Tunnel'] == "True":
        ## Create/Edit the 2nd IKE Gateway
        ike_data = ike_setup(csvrow['IKE_Name2'], shared_key,csvrow['Peer_Type'],csvrow['Local_Peer2'],csvrow['Remote_Peer2'],IKE_Crypto,passive_mode,csvrow['Tunnel_IP2'])
        logger.info("IKE2 - " + ("Edit ","Create ")[csvrow['NewIKE2']] + csvrow['IKE_Name2'] )
        logger.debug(ike_data)
        if csvrow['NewIKE2']:
            url = base_api_url + "ike-gateways?folder=Remote%20Networks"
            response = json.loads(post_api(token, url, ike_data))
        else:
            url = base_api_url + "ike-gateways/" + csvrow['IKE2_ID'] + "?folder=Remote%20Networks"
            response = json.loads(put_api(token, url, ike_data))
        if "_errors" in response:
            logger.error(response)
            raise SystemExit(1)

        ## Create/Edit the 2nd IPSec Tunnel
        ipsec_data = ipsec_setup(csvrow['IPSec_Name2'],csvrow['IKE_Name2'],IPsec_Crypto,csvrow['Monitor_IP2'])
        logger.info("IPSec2 - " + ("Edit ","Create ")[csvrow['NewIPSec2']] + csvrow['IPSec_Name2']  )
        logger.debug(ipsec_data)
        if csvrow['NewIPSec2']:
            url = base_api_url + "ipsec-tunnels?folder=Remote%20Networks"
            response = json.loads(post_api(token, url, ipsec_data))
        else:      
            url = base_api_url + "ipsec-tunnels/" + csvrow['IPSec2_ID'] + "?folder=Remote%20Networks"
            response = json.loads(put_api(token, url, ipsec_data))
        if "_errors" in response:
            logger.error(response)
            raise SystemExit(1)
    
    subnet = csvrow['Static_Route']
    if subnet.find(":") > 0:
        subnet_list = subnet.split(":")
    else:
        subnet_list = list((subnet,))
        
    ## Create/Edit the Remote Node
    rn_data = rn_setup(csvrow['Name'], csvrow['Dual_Tunnel'], csvrow['IPSec_Name1'],  csvrow['IPSec_Name2'], csvrow["region"], csvrow["SPN"], csvrow["BGP_AS"], csvrow["BGP_Local1"],csvrow["BGP_Local2"],csvrow["BGP_Peer1"],csvrow["BGP_Peer2"], subnet_list)
    logger.info("Remote Network - " + ("Edit ","Create ")[csvrow['NewRN']] + csvrow['Name']  )
    logger.debug(json.dumps(rn_data))
    if csvrow['NewRN']:
        url = base_api_url + "remote-networks?folder=Remote%20Networks"
        response = json.loads(post_api(token, url, rn_data))
    else: 
        url = base_api_url + "remote-networks/" + csvrow['RN_ID'] + "?folder=Remote%20Networks"
        response = json.loads(put_api(token, url, rn_data))
    if "_errors" in response:
        logger.error(response)
        raise SystemExit(1)
    return True

    
def delete_entries(csvrow):
    ## If the Remote Network Exists, delete it
    if 'RN_ID' in csvrow:
        logger.info("RN - Delete "+ csvrow['Name'])
        url = base_api_url + "remote-networks/" + csvrow['RN_ID'] + "?folder=Remote%20Networks"
        response = json.loads(delete_api(token, url))
        if "_error" in response:
            logger.error(response["_error"])
            raise SystemExit(1)
    ## If the IPSec Tunnel 1 Exists, delete it
    if 'IPSec1_ID' in csvrow:
        logger.info("IPSec1 - Delete "+ csvrow['IPSec_Name1'])
        url = base_api_url + "ipsec-tunnels/" + csvrow['IPSec1_ID'] + "?folder=Remote%20Networks"
        response = json.loads(delete_api(token, url))
        if "_errors" in response:
            logger.error(response)
            raise SystemExit(1)
    ## If the IPSec Tunnel 2 Exists, delete it   
    if 'IPSec2_ID' in csvrow:
        logger.info("IPSec2 - Delete "+ csvrow['IPSec_Name2'])
        url = base_api_url + "ipsec-tunnels/" + csvrow['IPSec2_ID'] + "?folder=Remote%20Networks"
        response = json.loads(delete_api(token, url))
        if "_errors" in response:
            logger.error(response)
            raise SystemExit(1)
    ## If the IKE Gateway 1 Exists, delete it
    if 'IKE1_ID' in csvrow:
        logger.info("IKE1 - Delete "+ csvrow['IKE_Name1'])
        url = base_api_url + "ike-gateways/" + csvrow['IKE1_ID'] + "?folder=Remote%20Networks"
        response = json.loads(delete_api(token, url))
        if "_errors" in response:
            logger.error(response)
            raise SystemExit(1)
    ## If the IKE Gateway 2 Exists, delete it
    if 'IKE2_ID' in csvrow:
        logger.info("IKE2 - Delete "+ csvrow['IKE_Name1'])
        url = base_api_url + "ike-gateways/" + csvrow['IKE2_ID'] + "?folder=Remote%20Networks"
        response = json.loads(delete_api(token, url))
        if "_errors" in response:
            logger.error(response)
            raise SystemExit(1)
    return True

if __name__ == '__main__':
    create_work = True
    commit_flag = False
    logging.basicConfig(level=None)    
    ## Read the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--add", help = "add the bulk load items, blank is the same as add", action="store_true")
    parser.add_argument("-d", "--delete", help = "delete any of the bulk load items if they exist", action="store_true")
    parser.add_argument("-c", "--commit", help = "Commit the config after add/edit/delete", action="store_true")
    parser.add_argument("-l", "--log", help = "set the log level [INFO,DEBUG]")
    args = parser.parse_args()
    if args.add:
        create_work = True
    if args.delete:
        create_work = False
    if args.commit:
        commit_flag= True
    if args.log and args.log in ['INFO','DEBUG']:
        logger.setLevel(args.log)

    print(("Delete","Create/Edit")[create_work],"bulk remote network data")
    print(".")
    # Set the environment
    load_config()
    print(".")
    # Load up the CSV
    load_csv()
    print(".")
    token = get_new_token()
    print(".")
    load_current_state(token)
    print(".")
  # Now process the CSV
    for csvrow in csvdict:
        # First check that the line contains a valid Region and SPN. Also check if the RN/IPSec/IKE exists and flag it.
        csvrow['IKE_Name1'] = csvrow['Name'] + "-IKE1"
        csvrow['IKE_Name2'] = csvrow['Name'] + "-IKE2"
        csvrow['IPSec_Name1'] = csvrow['Name'] + "-IPSec1"
        csvrow['IPSec_Name2'] = csvrow['Name'] + "-IPSec2"
        print("processing CSV entry: " + csvrow['Name'])
        check_rn(csvrow)
        # If debugging, print the row in the CSV file we are working on, with the additional working attributes
        logger.debug("CSV Row with working fields, e.g. 'aggregate_region', 'region''NewRN', 'NewIPSec1', 'NewIPSec2', 'NewIKE1', 'NewIKE2', RN_ID, IPSec1_ID, IPSec2_ID, IKE1_ID, IKE2_ID")
        logger.debug(csvrow)
        ## Check if we are adding or deleting
        if create_work == True:
            ### Add argument was selected (or nothing specified)
            create_config(csvrow)
        ### Delete argument was selected
        else:
            delete_entries(csvrow)
    if commit_flag:
        logger.info("commit_config")
        commit_config()

