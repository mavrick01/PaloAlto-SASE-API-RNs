# PACMAN-API-RNs

**Automatic provisioning of Remote Networks on Palo Alto Networks Prisma Cloud Managed**
NOTE: This does require the tenancy to be part of the SASE Portal

This Python3 script can simplifiy the deployment of a Remote Network configurations.

This script requires 2 files 
config.yaml
<XXXX>.csv
  
**config.yaml layout**
In the config file you need to define the following:
 Markup : - clientID - You will receive this when you configure a service API account
- clientSecret - You will receive this when you configure a service API account
-tenantID - Generally the number that is the name of the email address of the client_id, prefixed with "tsg_id:". With Multi-tenancy, this can be a tenancy deeper in the hierarchy 
-PassiveMode - Defined is if the Prisma Access IPSec is Dynamic (true) or Static (false)
-PSK - The pre-shared key for all IPSec Tunnels. 
-csvFile - The file referenced as <XXXX>.csv above. This is where your configs are defined
  
**CSV file layout**
The CSV file must have the all the following columns. They can be blank where relevant
  Name - Remote Network Name
  Compute_Region - Name of the Compute Region as stated in the Portal page
  SPN - name of the Security Processing Node for the site. Bandwidth must be allocated to the Compute Region before provisoning
  Dual_Tunnel - Set as True to configure the Secondary Tunnel as well
  Tunnel_IP1 - If the Tunnel is static, defined the Static IP address of the Primary Tunnel. Leave blank if Dynamic
  Tunnel_IP2 - If the Tunnel is static, defined the Static IP address of the Secondary Tunnel. Leave blank if Dynamic
  Peer_Type - If you define Peers, you need to specify one of the following types: "ipaddr" "keyid" "fqdn" "ufqdn"
  Local_Peer1 - Primary Local peer parameter. E.g if you select ufqdn it would be something like ipsec@acme.com
  Remote_Peer1 - Primary Remote peer parameter
  Local_Peer2 - Secondary Local peer parameter
  Remote_Peer2 - Secondary Remote peer parameter
  Monitor_IP1 - If defined, turns on Monitoring and polls the IP address in the Primary IPSec Tunnel
  Monitor_IP2 - If defined, turns on Monitoring and polls the IP address in the Primary IPSec Tunnel
  BGP_AS - If defined will provision the BGP Peer AS
  BGP_Local1 - If defiend will provision the Primary BGP Local IP - must be defined with the AS as a minimum to turn on BGP
  BGP_Peer1 - If defined, Primary BGP Peer IP Address
  BGP_Local2 - If defiend will provision the Secondary BGP Local IP
  BGP_Peer2 - If defined, Secondary BGP Peer IP Address (currently needs intervention to select the flag in the portal)
  Static_Route - Define a list of IP NetMasks for Static routes. Multiple addresses can be added with the delimeter of : between then. e.g. 192.168.1.0/24:192.168.2.0/24
  Peer_Type - ,Local_Peer1,Remote_Peer1,Local_Peer2,Remote_Peer2,Monitor_IP1,Monitor_IP2,BGP_AS,BGP_Local1,BGP_Peer1,BGP_Local2,BGP_Peer2,Static_Route
