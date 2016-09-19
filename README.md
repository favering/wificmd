# wificmd

Wificmd, a wifi command tool to do wifi connection/disconnection with AP on Linux(Only works on Python3).

Features:
- Security on connection.
  Typically , Linux comes NetworkManager will switch between stored AP unexpectedly.
  However, if -s was specified when using \"wificmd con\", it will always try to connect with that AP. This is useful when doing some penetration work on wifi.
- Support multiple wireless interface connection.
- A list of core wifi function can be imported in your python code to write your owned wifi connection tool.
- Networkmanager.

Usage:
wificmd.py [-h] {scan,stat,con,discon,add,del,show}
- wificmd.py scan [-h] [-i INTERFACE]          
  Scan for in-range AP. 
- wificmd.py stat [-h] [-i INTERFACE]          
  Show wificmd connection status. 
- wificmd.py con [-h] [-s SSID] [-i INTERFACE]        
  Connect to added AP. 
- wificmd.py discon [-h] [-i INTERFACE]        
  Disconnect from AP. 
- wificmd.py add <ssid> [-h] [-p PASSWORD]     
  Save a AP profile. 
- wificmd.py del [-h] [-s SSID]                
  Delete saved AP profile. 
- wificmd.py show [-h] [-k KEYWORD]            
  Show saved AP profile. 

Bugs:
- Can not set the system DNS server on Ubuntu.
- Cannot co-work with Linux comes NetworkManager. So before use wificmd, NetworkManager should be disabled by running "service network-manager stop" and "service wpa_supplicant stop"
- And maybe other bugs.


