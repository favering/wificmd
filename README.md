# wificmd

Wificmd, a wifi cammand tool to do wifi connection/disconnection with AP on Linux(Only works on Python3).

Features:
- Security on connection.
  Typically , Linux comes NetworkManager will switch between stored AP unexpectedly.
  However, if -s was specified when using \"wificmd con\", it will always try to connect with that AP. This is useful when doing some penetration work on wifi.
- Support multiple wireless interface connection.
- A list of core wifi function can be imported in your python code to write your owned wifi connection tool.
- Networkmanager.

Bugs:
- Can not set the system DNS server on Ubuntu.
- And maybe other bugs.
