# PaloAlto SASE-API-RNs

## Automatic provisioning of Remote Networks on Palo Alto Networks Prisma Cloud Managed ##
NOTE: This requires that the tenancy to be part of the SASE Portal

This Python3 script can simplify the deployment of a Remote Network configurations.

This script requires 2 files: 
* config.yaml
* _XXXX_.csv
  
**config.yaml layout**
In the config file you need to define the following:
  * __clientID__ - You will receive this when you configure a service API account
  * __clientSecret__ - You will receive this when you configure a service API account
  * __tenantID__ - (Optional) IF the client ID is an email address and is not defined, it will extract the Tenant ID from the client ID. With Multi-tenancy, this can be a tenancy deeper in the hierarchy (you must prefix the tenancy number with "tsg_id:"
  * __PassiveMode__ - (Optional) Defined is if the Prisma Access IPSec tunnels are passive . If not defined default is they are not set to Passive Mode 
  * __PSK__ - The pre-shared key for all IPSec Tunnels. 
  * __csvFile__ - The file referenced as <XXXX>.csv above. This is where your configs are defined
  
**CSV file layout**
The CSV file must have the all the following columns. They can be blank where relevant
  * __Name__ - Remote Network Name
  * __Compute_Region__ - Name of the Compute Region as stated in the Portal page
  * __SPN__ - name of the Security Processing Node for the site. Bandwidth must be allocated to the Compute Region before provisoning
  * __Dual_Tunnel__ - Set as True to configure the Secondary Tunnel as well
  * __Tunnel_IP1__ - If the Tunnel is static, defined the Static IP address of the Primary Tunnel. Leave blank if Dynamic
  * __Tunnel_IP2__ - If the Tunnel is static, defined the Static IP address of the Secondary Tunnel. Leave blank if Dynamic
  * __Peer_Type__ - If you define Peers, you need to specify one of the following types: "_ipaddr_" "_keyid_" "_fqdn_" "_ufqdn_"
  * __Local_Peer1__ - Primary Local peer parameter. E.g if you select _ufqdn_ it would be something like _ipsec@acme.com_
  * __Remote_Peer1__ - Primary Remote peer parameter
  * __Local_Peer2__ - Secondary Local peer parameter
  * __Remote_Peer2__ - Secondary Remote peer parameter
  * __Monitor_IP1__ - If defined, turns on Monitoring and polls the IP address in the Primary IPSec Tunnel
  * __Monitor_IP2__ - If defined, turns on Monitoring and polls the IP address in the Primary IPSec Tunnel
  * __BGP_AS__ - If defined will provision the BGP Peer AS
  * __BGP_Local1__ - If defiend will provision the Primary BGP Local IP - must be defined with the AS as a minimum to turn on BGP
  * __BGP_Peer1__ - If defined, Primary BGP Peer IP Address
  * __BGP_Local2__ - If defiend will provision the Secondary BGP Local IP
  * __BGP_Peer2__ - If defined, Secondary BGP Peer IP Address (currently needs intervention to select the flag in the portal)
  * __Static_Route__ - Define a list of IP NetMasks for Static routes. Multiple addresses can be added with the delimeter of __:__ between them e.g. _192.168.1.0/24:192.168.2.0/24_
