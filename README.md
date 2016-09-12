# wificmd

Wificmd, a wifi cammand tool to do wifi connection/disconnection with AP on Linux(Only works on Python3).

Features:
- Security on connection.
  Typically , Linux comes NetworkManager will switch between stored AP unexpectedly.
  However, if -s was specified when using \"wificmd con\", it will always try to connect with that AP. This is useful when doing some penetration work on wifi.
- Support multiple wireless interface connection.
- A list of core wifi function can be imported in your python code to write your owned wifi connection tool.
- Networkmanager.

Usage:
wificmd.py [-h] {scan,stat,con,discon,add,del,show}
- wificmd.py scan [-i INTERFACE]          
  Scan for in-range AP. Use 'wificmd scan -h' for more help
- wificmd.py stat [-i INTERFACE]          
  Show wificmd connection status. Use 'wificmd stat -h' for more help
- wificmd.py con [-s SSID] [-i INTERFACE] 
  Connect to added AP. Use 'wificmd con -h' for more help
- wificmd.py discon [-i INTERFACE]        
  Disconnect from AP. Use 'wificmd discon -h' for more help
- wificmd.py add <ssid> [-p PASSWORD]     
  Save a AP profile. Use 'wificmd add -h' for more help
- wificmd.py del [-s SSID]                
  Delete saved AP profile. Use 'wificmd del -h' for more help
- wificmd.py show [-k KEYWORD]            
  Show saved AP profile. Use 'wificmd show -h' for more help

Bugs:
- Can not set the system DNS server on Ubuntu.
- And maybe other bugs.


