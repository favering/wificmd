#! /usr/bin/env python3

################################ wificmd.py core library start ###############################

import json
import os
import subprocess
import re
import time

wifi_conf_file = "/etc/wificmd/wificmd.conf"
wpa_conf_file = "/etc/wificmd/wpa_supplicat.conf"
wpa_ctrl_sock = "/var/run/wifi_wpa_sup"
wpa_action_file = "/etc/wificmd/wpa_action.py"
wpa_action_file_ctn = \
'''#! /usr/bin/env python3

import sys
import subprocess

if sys.argv[2] == 'CONNECTED':
    cmd = ['dhclient', sys.argv[1]]
elif sys.argv[2] == 'DISCONNECTED':
    cmd = ['ip', 'addr', 'flush', sys.argv[1]]
else:
    sys.exit(0)
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
proc.communicate()
'''

class ProfileNotFoundError(Exception):
    def __init__(self, ssid):
        self.ssid = ssid

class CommandNotSupportedError(Exception):
    def __init__(self, cmd):
        self.cmd = cmd

class CreateFileError(Exception):
    def __init__(self, err):
        self.err = err

class DeviceBusyError(Exception):
    def __init__(self, wface_name):
        self.wface_name = wface_name

class WPAConfigEmptyError(Exception):
    pass


class APProfile:
    def __init__(self, ssid, encryption='OPEN', password=''):
        self.ssid = ssid
        self.encryption = encryption
        self.password = password

class AccessPoint:
    def __init__(self, ssid, mac, signal, encryption='OPEN', password=None):
        self.ssid = ssid
        self.mac = mac
        self.signal = signal
        self.encryption = encryption
        self.password = password

class WirelessInterface:
    def __init__(self, name, mode, mac, essid, signal, state):
        self.name = name
        self.mode = mode
        self.mac = mac
        self.essid = essid
        self.signal = signal
        self.state = state

def save_ap_profile(profile):
    """
    Save a profile of an AP.
    :param profile:
    :return:
    :except: CreateFileError raised when create profile file failed.
    """
    _check_file(wifi_conf_file)
    d = {}
    with open(wifi_conf_file) as f:
        s = f.read()
        if len(s) == 0:
            d = {}
        else:
            d = json.loads(s)

    d[profile.ssid] = (profile.encryption, profile.password)
    with open(wifi_conf_file, 'w') as f:
        json.dump(d, f, indent=4)

def clear_ap_profile(ssid=None):
    """
    Clear the saved profile of an AP identified by ssid.
    :param ssid:
    :return:
    :except:  ProfileNotFoundError raised when ssid not found in profile.
              CreateFileError raised when create profile file failed.
    """
    _check_file(wifi_conf_file)
    d = {}
    with open(wifi_conf_file) as f:
        s = f.read()
        if len(s) == 0:
            d = {}
        else:
            d = json.loads(s)
    if ssid:
        if ssid not in d:
            raise ProfileNotFoundError(ssid)
        d = {k: d[k] for k in d if k != ssid}
    else:
        d = {}
    with open(wifi_conf_file, 'w') as f:
        json.dump(d, f, indent=4)


def list_ap_profile(keyword=None):
    """
    Get profiles which has a substring of keyword either in ssid, password or any other field.
    :param keyword:
    :return: if keyword is None, return all AP profile.
    :except: CreateFileError raised when create profile file failed.
    """
    _check_file(wifi_conf_file)
    with open(wifi_conf_file) as f:
        s = f.read()
        if len(s) == 0:
            return {}
        d = json.loads(s)
        if keyword is not None:
            return {ssid: APProfile(ssid, d[ssid][0], d[ssid][1]) \
                    for ssid in d if keyword in ssid or keyword in d[ssid][0] or keyword in d[ssid][1]}
        else:
            return {ssid: APProfile(ssid, d[ssid][0], d[ssid][1]) for ssid in d}


def _check_file(fpath):
    """
    Check file/diretory existence, create it if file/diretory do not exist.
    :param fpath: path name
    :return:
    """
    try:
        dir_name = os.path.dirname(fpath)
        if not os.path.isdir(dir_name):
            os.mkdir(dir_name)
            cmd = ['chmod', '777', dir_name]
            subprocess.check_call(cmd)

        if not os.path.isfile(fpath):
            open(fpath, 'w+').close()
            cmd = ['chmod', '666', fpath]
            subprocess.check_call(cmd)
    except OSError as e:
        raise CreateFileError(e.strerror)


def _make_wpa_action_file():
    """
    Write wpa_supplicant's action file, which passed to wpa_cli process.
    :return:
    """
    _check_file(wpa_action_file)
    with open(wpa_action_file, 'w') as f:
        f.write(wpa_action_file_ctn)
    subprocess.check_call(['chmod', '+x', wpa_action_file],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _write_wpa_conf(d):
    """
    Write wpa_supplicat.conf file
    :param d: AP info dictionary as {ssid: APProfile}
    :return:
    """
    _check_file(wpa_conf_file)
    with open(wpa_conf_file, 'w') as f:
        f.write("ctrl_interface=DIR=" + wpa_ctrl_sock)
        for ssid, profile in d.items():
            f.write("\n")
            f.write("network={\n")
            f.write("\tssid=\"{0}\"\n".format(ssid))
            # OPEN
            if profile.encryption == "OPEN":
                f.write("\tkey_mgmt=NONE\n")
            # WPA/WPA2
            elif profile.encryption == "WPA/2":
                f.write("\tkey_mgmt=WPA-PSK\n")
                f.write("\tpsk=\"{0}\"\n".format(profile.password))
            f.write("}")
        f.write("\n")

def _net_status(wface_name):
    """
    Return the wface_name' ip level status, such as ip, gateway
    :param wface_name:
    :return: a tuple as (ip, gateway, net)
    """
    cmd = ['ip', 'addr', 'show', wface_name]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        raise CommandNotSupportedError(cmd[0])
    out_lines, err_lines = proc.communicate()
    if proc.returncode != 0:
        raise NotImplementedError(wface_name + ':' + err_lines.decode('utf-8'))

    out_lines = out_lines.decode('utf-8')
    match = re.search(r'\s+inet\s+([\d\./]+)\s+', out_lines)
    ip = None if match is None else match.group(1)

    if ip is None:
        return None, None, None

    cmd = ['ip', 'route']
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        raise CommandNotSupportedError(cmd[0])
    out_lines, err_lines = proc.communicate()
    if proc.returncode != 0:
        raise NotImplementedError(wface_name + ':' + err_lines.decode('utf-8'))

    out_lines = out_lines.decode('utf-8')
    match = re.search(r'([\w\d\.]+)\s+via\s+([\d\.]+)\s+dev\s+' + wface_name, out_lines)
    net = None if match is None else match.group(1)
    gateway = None if match is None else match.group(2)
    return ip, gateway, net

def _wpa_status(wface_name):
    """
    Return the wface_name' wifi status , such as essid, signal level.
    :param wface_name:
    :return: a tuple as (essid, signal)
    """
    cmd = ['iwconfig', wface_name]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        raise CommandNotSupportedError(cmd[0])
    out_lines, err_lines = proc.communicate()
    if proc.returncode != 0:
        raise NotImplementedError(wface_name + ':' + err_lines.decode('utf-8'))

    out_lines = out_lines.decode('utf-8')
    match = re.search(r'ESSID:\"(.+)\"', out_lines)
    if match is None:
        essid = None
        signal = 0
    else:
        essid = match.group(1)
        signal = re.search(r'Signal\s+level=(-\d+)\s+dBm', out_lines).group(1)
    return essid, int(signal)

def _pidof_wpa_supplicant_on(wface_name):
    """
    Return the pid of wpa_supplicant process working on wface_name
    :param wface_name:
    :return: -1 if wpa_supplianct on wface_name not found
             else the pid of wpa_supplianct
    """
    cmd = ['ps', '-ef']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_lines = '\n' + proc.communicate()[0].decode()
    reg_wpa = r"\n\w+\s+(\d+)\s+\d+.+wpa_supplicant\s+-i\s+" + wface_name + r"\s+-Dwext"
    rst = re.search(reg_wpa, out_lines)
    return -1 if rst is None else rst.group(1)

def _pidof_wpa_cli_action_on(wface_name):
    """
    Return the pid of wpa_cli process working on wface_name, which response for
    the action to the wpa_supplicant's connection or disconnection
    :param wface_name:
    :return: -1 if wpa_cli on wface_name not found
             else the pid of wpa_cli
    """
    cmd = ['ps', '-ef']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_lines = '\n' + proc.communicate()[0].decode()
    reg_wpa = r"\n\w+\s+(\d+)\s+\d+.+wpa_cli\s+-i\s+" + wface_name \
              + r"\s+-a\s+" + wpa_action_file
    rst = re.search(reg_wpa, out_lines)
    return -1 if rst is None else rst.group(1)

def _wface_stat(wf_name):
    """
    Return the wf_name's power status(UP/DOWN)
    :param wf_name:
    :return:
    """
    cmd = ['ip', 'link', 'show', wf_name]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        raise CommandNotSupportedError(cmd[0])
    out_lines, err_lines = proc.communicate()
    if proc.returncode != 0:
        raise NotImplementedError(wf_name + ':' + err_lines.decode('utf-8'))
    out_lines = out_lines.decode('utf-8')
    match = re.search(wf_name + r'\s*:\s*<.*\bUP\b.*>', out_lines)
    return 'DOWN' if match is None else 'UP'

def list_wfaces(mode=None, state=None):
    '''
    Return all wireless interface on this computer.
    :param mode: wireless interface working mode,
    :param state: wireless interface state(UP/DOWN)
    :return: a dictionary with interface name as key, a WirelessInterface instance as value.
            example: {'wlan0': WirelessInterface,
                      'wlan1': WirelessInterface}
    :except: CommandNotSupportedError(iwconfig, ip)
    '''

    cmd = ['iwconfig']
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        raise CommandNotSupportedError(cmd[0])
    out_lines = proc.communicate()[0]

    # find the beging position of each interface
    out_lines = '\n' + out_lines.decode('utf-8')
    begin_matchs = list(re.finditer(r'\n(\w+)', out_lines))

    # parse each interface to store into result
    result = {}
    for idx in range(len(begin_matchs)):
        if idx == len(begin_matchs) - 1:
            lines = out_lines[begin_matchs[idx].start():]
        else:
            lines = out_lines[begin_matchs[idx].start():begin_matchs[idx + 1].start()]

        # wireless interface name
        wf_name = begin_matchs[idx].group(1)
        # mode
        wf_mode = re.search(r'Mode:\s*(\w+)', lines).group(1)
        # essid signal
        match = re.search(r'ESSID:\"(.+)\"', out_lines)
        if match is None:
            wf_essid = None
            wf_signal = 0
        else:
            wf_essid = match.group(1)
            wf_signal = re.search(r'Signal\s+level=(-\d+)\s+dBm', out_lines).group(1)

        # get the wireless interface's status(UP/DOWN)
        wf_state = _wface_stat(wf_name)

        # construct a WirelessInterface instance
        wface = WirelessInterface(wf_name, wf_mode, None, wf_essid, int(wf_signal),wf_state)
        result[wf_name] = wface

    # filter by args
    if mode:
        result = {nm: result[nm] for nm in result if result[nm].mode == mode}
    if state:
        result = {nm: result[nm] for nm in result if result[nm].state == state}
    return result

def scan(wface_name):
    """
    Scan for in range AP.
    :param wface_name: wireless interface used to scan
    :return: dictionary as: {ssid: AccessPoint}
    :except: DeviceBusyError, CommandNotSupportedError
    """

    cmd = ['iwlist', wface_name, 'scan']
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        raise CommandNotSupportedError(cmd[0])
    out_lines, err_lines = proc.communicate()

    if proc.returncode != 0:
        if proc.returncode == 240:
            raise DeviceBusyError(wface_name)
        else:
            raise NotImplementedError(wface_name + ':' + err_lines.decode('utf-8'))

    out_lines = '\n' + out_lines.decode('utf-8')
    # find the beginning position of each AP infomation
    begin_reg = r'Cell\s+\d+'
    begin_matchs = list(re.finditer(begin_reg, out_lines))

    # parse each AP to store in result
    result = {}
    for idx in range(len(begin_matchs)):
        if idx == len(begin_matchs) - 1:
            lines = out_lines[begin_matchs[idx].start():]
        else:
            lines = out_lines[begin_matchs[idx].start():begin_matchs[idx + 1].start()]

        mac = re.search(r'Address:\s+(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})', lines).group(1)
        ssid = re.search(r'ESSID:\s*\"(.+)\"', lines).group(1)
        signal = re.search(r'Signal\s+level=(-\d+)\s+dBm', lines).group(1)
        signal = int(signal)
        if re.search(r'IE:.+WPA2', lines) is not None:
            enc = 'WPA/2'
        elif re.search(r'IE:.*WPA', lines) is not None:
            enc = 'WPA/2'
        else:
            enc = 'OPEN'

        # in a roaming environment, only report the most strong signal AP
        if ssid in result:
            if result[ssid].signal >= signal:
                continue
        result[ssid] = AccessPoint(ssid, mac, signal, enc)
    return result

def stat(wface_name):
    """
    Return the wificmd's connection status
    :param wface_name: wireless interface name
    :return: A dictionary represent the wificmd's status.
    """
    d = {}
    d['wface_name'] = wface_name
    d['wpa_supp_pid'] = _pidof_wpa_supplicant_on(wface_name)
    d['wpa_cli_act_pid'] = _pidof_wpa_cli_action_on(wface_name)
    d['essid'], d['signal'] = (None, None) if d['wpa_supp_pid'] == -1 else _wpa_status(wface_name)
    d['ip'], d['gateway'], d['net'] = _net_status(wface_name)

    return d

def con(wface_name, ap_profiles):
    """
    Connect to ap.
    :param wface_name: wireless interface use to connect
    :param ap_profiles: a list of access points to connect
    :return:
    :except: CommandNotSupportedError
    """

    if len(ap_profiles) == 0:
        raise WPAConfigEmptyError()

    # write an empty wpa configuration file
    _write_wpa_conf({})

    # launch wpa_supplicant
    cmd = ['wpa_supplicant', '-i', wface_name, '-Dwext', '-c', wpa_conf_file, '-B']
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        raise CommandNotSupportedError(cmd[0])
    err_lines = proc.communicate()[1]
    if proc.returncode != 0:
        raise NotImplementedError(wface_name + ':' + err_lines.decode())

    # make wpa_supplicant action(CONNECTED or DISCONNECTED) file
    try:
        _make_wpa_action_file()
    except:
        discon(wface_name)
        raise

    # launch wpa_cli to specify the action when the wpa_supplicant connect or disconnect
    cmd = ['wpa_cli', '-i', wface_name, '-a', wpa_action_file, '-p', wpa_ctrl_sock]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        discon(wface_name)
        raise CommandNotSupportedError(cmd[0])

    # Because wpa_cli run as daemon with option '-B' cannot start -a script correctly(as I
    # tested),so wpa_cli run as normal proccess will not return at this moment,so it's
    # impossiable to check wpa_cli' return code. It's better to sleep a little while.
    time.sleep(1)

    #write the real wpa configuration file
    _write_wpa_conf(ap_profiles)

    #tell the wpa_supplicant to reconfigure
    cmd = ['wpa_cli', '-i', wface_name, '-p', wpa_ctrl_sock, 'reconfigure']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err_lines = proc.communicate()[1]
    if proc.returncode != 0:
        discon(wface_name)
        raise NotImplementedError(cmd + ':' + err_lines.decode('utf-8'))

def discon(wface_name):
    """
    Disconnect wface_name from AP.
    :param wface_name:
    :return:
    """

    st = stat(wface_name)

    # clear route
    if st['net'] is not None:
        cmd = ['ip', 'route', 'del', st['net']]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err_lines = proc.communicate()[1].decode()
        if proc.returncode != 0:
            raise NotImplementedError(wface_name + ':' + err_lines)

    # clear ip
    if st['ip'] is not None:
        cmd = ['ip', 'addr', 'flush', wface_name]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err_lines = proc.communicate()[1].decode()
        if proc.returncode != 0:
            raise NotImplementedError(wface_name + ':' + err_lines)

    # kill wpa_cli response for action
    if st['wpa_cli_act_pid'] != -1:
        cmd = ['kill', '-9', st['wpa_cli_act_pid']]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err_lines = proc.communicate()[1].decode()
        if proc.returncode != 0:
            raise NotImplementedError(wface_name + ':' + err_lines)

    # kill wpa_supplicant
    if st['wpa_supp_pid'] != -1:
        # disconnect
        cmd = ['wpa_cli', 'discon', '-i', wface_name, '-p', wpa_ctrl_sock]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err_lines = proc.communicate()[1].decode()
        if proc.returncode != 0:
            raise NotImplementedError(wface_name + ':' + err_lines)

        # terminate
        cmd = ['wpa_cli', 'terminate', '-i', wface_name, '-p', wpa_ctrl_sock]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err_lines = proc.communicate()[1].decode()
        if proc.returncode != 0:
            raise NotImplementedError(wface_name + ':' + err_lines)

    # wait for all above complete
    time.sleep(0.2)

################################ wificmd.py core library end   ###############################




################################ below is user level code ###############################


class NotSupportedEncrytionError(Exception):
    def __init__(self, enc):
        self.enc = enc

class NoWirelessInterfaceError(Exception):
    pass

class WirelessInterfaceNotFoundError(Exception):
    def __init__(self, wface_name):
        self.wface_name = wface_name

class WirelessInterfaceModeError(Exception):
    def __init__(self, wface_name, mode):
        self.wface_name = wface_name
        self.mode = mode

class NoManagedWirelessInterfaceError(Exception):
    pass

class APNotInRangeError(Exception):
    def __init__(self, ssid_list=[], specified=False):
        self.ssid_list = ssid_list
        self.specified = specified


class ProfileEncryptionError(Exception):
    def __init__(self, ssid, old, new):
        self.old = old
        self.new = new

class NoAPProfile(Exception):
    pass

def network_manager_status():
    out_lines = subprocess.check_output(["ps", "-e"])
    if not "NetworkManager" in out_lines:
        return False
    return True

def stop_network_manager():
    subprocess.check_output(["service", "network-manager", "stop"])

def _make_wface_up(wface_name):
    """
    Make wireless interface up. Similar to "ifconfig <wface> up"
    :param wface_name:
    :return:
    """
    subprocess.check_call(['ip', 'link', 'set', wface_name, 'up'])

def _scan(args):
    """
    [User function]
    Scan for in range AP.
    :param wface_name: wireless interface used to scan
    :return:
    """
    wface_name = args.interface

    # check the specified wireless interface
    if wface_name is not None:
        all_wface = list_wfaces()
        if wface_name not in all_wface:
            raise WirelessInterfaceNotFoundError(wface_name)
        # check wireless interface's status
        if all_wface[wface_name].state == 'DOWN':
            _make_wface_up(wface_name)
        # currently suppose only managed mode can do scan
        if all_wface[wface_name].mode != 'Managed':
            raise WirelessInterfaceModeError(wface_name, all_wface[wface_name].mode)
    # choise a wireless interface to scan
    else:
        if len(list_wfaces()) == 0:
            raise NoWirelessInterfaceError()
        mgd_wfaces = list_wfaces(mode='Managed')
        if len(mgd_wfaces) == 0:
            raise NoManagedWirelessInterfaceError()
        wface_name = list(mgd_wfaces.keys())[0]
        if mgd_wfaces[wface_name].state == 'DOWN':
            _make_wface_up(wface_name)

    # start scan
    _msg_print.info("Using %s to scan..." % wface_name, end='')
    try:
        result = scan(wface_name)
    except:
        _msg_print.info('')
        _msg_print.error(e)
        raise
    _msg_print.info("Done")
    _format_output_scan_result(result)

def _stat(args):
    """
    [User function]
    Get the wificmd's connection status.
    :param wface_name:
    :return:
    """
    wface_name = args.interface
    con_status = []
    all_wface = list_wfaces()

    # get the wface_name' status
    if wface_name is not None:
        if wface_name not in all_wface:
            raise WirelessInterfaceNotFoundError(wface_name)
        con_status.append(stat(wface_name))
    # get each wireless interface' status
    else:
        if len(list_wfaces()) == 0:
            raise NoWirelessInterfaceError()
        con_status = [stat(wface) for wface in all_wface]

    _format_output_con_status(con_status)

def _con(args):
    """
    [User function]
    Connect to AP.
    :param wface_name: wireless interface name to use to connect
    :param ssid: AP to connect
    :return:
    """
    wface_name = args.interface
    ssid = args.ssid

    # check the specified wireless interface
    if wface_name is not None:
        all_wface = list_wfaces()
        if wface_name not in all_wface:
            raise WirelessInterfaceNotFoundError(wface_name)
        # check wireless interface's status
        if all_wface[wface_name].state == 'DOWN':
            _make_wface_up(wface_name)
        # currently suppose only managed mode can do connect
        if all_wface[wface_name].mode != 'Managed':
            raise WirelessInterfaceModeError(wface_name, all_wface[wface_name].mode)
    # choise a right wireless interface to connect
    else:
        if len(list_wfaces()) == 0:
            raise NoWirelessInterfaceError()
        mgd_wfaces = list_wfaces(mode='Managed')
        if len(mgd_wfaces) == 0:
            raise NoManagedWirelessInterfaceError()
        wface_name = list(mgd_wfaces.keys())[0]
        if mgd_wfaces[wface_name].state == 'DOWN':
            _make_wface_up(wface_name)

    _msg_print.info("Using %s" % wface_name)

    # check AP profiles
    saved_profile = list_ap_profile()
    scan_result = scan(wface_name)

    # check specified ssid
    if ssid is not None:
        if ssid not in scan_result:
            raise APNotInRangeError(list([ssid]), specified=True)
        if scan_result[ssid].encryption == 'OPEN':
            if ssid not in saved_profile:
                save_ap_profile(APProfile(ssid))
            else:
                # check if encryption has changed
                if saved_profile[ssid].encryption != 'OPEN':
                    raise ProfileEncryptionError(ssid, saved_profile[ssid].encryption, 'OPEN')
        elif scan_result[ssid].encryption == 'WPA/2':
            if ssid not in saved_profile:
                pswd = input("Input password for '%s': " % ssid)
                save_ap_profile(APProfile(ssid, 'WPA/2', pswd))
            else:
                # check if encryption has changed
                if saved_profile[ssid].encryption != 'WPA/2':
                    raise ProfileEncryptionError(ssid, saved_profile[ssid].encryption, 'WPA/2')
        else:
            raise NotSupportedEncrytionError(scan_result[ssid].encryption)

    # check saved ssid
    else:
        if len(saved_profile) == 0:
            raise NoAPProfile()

        # report error when there's no saved ap in range
        ap_in_range = {k: saved_profile[k] for k in saved_profile if k in scan_result}
        if len(ap_in_range) == 0:
            raise APNotInRangeError(saved_profile.keys())

        # check if any ap'encryption has changed
        for k in ap_in_range:
            if ap_in_range[k].encryption != scan_result[k].encryption:
                raise ProfileEncryptionError(ssid, ap_in_range[k].encryption,
                                             scan_result[k].encryption)
        _msg_print.info("Avaiable in range AP: {}".format(list(ap_in_range.keys())))

    # connect
    if ssid is not None:
        _msg_print.info("Connecting to %s..." % ssid, end='')
        con(wface_name, {ssid: list_ap_profile()[ssid]})
    else:
        _msg_print.info("Connecting to any avaiable AP...", end='')
        con(wface_name, list_ap_profile())
    _msg_print.info('Done')

def _discon(args):
    """
    [User function]
    Disconnect from AP.
    :param wface_name:
    :return:
    """
    wface_name = args.interface
    all_wface = list_wfaces()
    target_wface = []

    # prepare to disconect the specified wireless interface
    if wface_name is not None:
        if wface_name not in all_wface:
            raise WirelessInterfaceNotFoundError(wface_name)
        target_wface.append(wface_name)
    # prepare to disconect all wireless interface
    else:
        if len(all_wface) == 0:
            raise NoWirelessInterfaceError()
        target_wface = all_wface.keys()

    # disconnect
    for wface in target_wface:
        discon(wface)
        _stat(wface)

def _show(args):
    """
    Show stored AP profile.
    :param args:
    :return:
    """

    d = list_ap_profile(args.keyword)
    _format_output_ap_profile(d)


def _add(args):
    """
    Add an AP profile to stored Profile list.
    :param args:
    :return:
    """
    if args.password is None:
        save_ap_profile(APProfile(args.ssid))
        _msg_print.info("Succeed in saving %s as OPEN encryption." % args.ssid)
    else:
        save_ap_profile(APProfile(args.ssid, 'WPA/2', args.password))
        _msg_print.info("Succeed in saving %s." % args.ssid)

def _del(args):
    """
    Delete an AP profile from stored Profile list.
    :param args:
    :return:
    """

    if args.ssid is None:
        _msg_print.warn("All stored password will be cleared!")
        _msg_print.info("(To clear a specified AP password, use \"wificmd del -s <ssid>\")")
        while True:
            choice = _msg_print.quest("Clear all password? Y/N: ").upper()
            if choice == 'Y':
                clear_ap_profile()
                _msg_print.info("Succeed in clearing all password.")
                return
            elif choice == 'N':
                return
            else:
                _msg_print.info("Only Y or N accepted")
                continue
    else:
        clear_ap_profile(args.ssid)
        _msg_print.info("Succeed in clearing password of '%s'" % args.ssid)

def _format_output_ap_profile(d):
    """
    Print AP profile.
    :param d: AP profile ditionary as {ssid: APProfile}
    :return:
    """
    ssid_max_len = 0 if len(d) == 0 else len(max(d.keys(), key=len))
    line_format = "{0}     {1:10}     {2}"
    f = lambda x: x if len(x) >= ssid_max_len else x + ' ' * (ssid_max_len - len(x))
    print(line_format.format(f('ssid'), 'encryption', 'password'))
    print(line_format.format(f('----'), '----------', '--------'))
    ssid_align_max = max(ssid_max_len, len('ssid'))
    for ssid, profile in d.items():
        print(line_format.format(ssid + ' ' * (ssid_align_max - len(ssid)),
                                 profile.encryption, profile.password))
    print("\nTotal %d" % len(d))

def _format_output_con_status(con_status):
    """
    Print connection status.
    :param con_status: a list of connection status
    :return:
    """
    for st in con_status:
        print("{0:20}".format(st['wface_name']), end='')
        fmt = " "*20
        if st['wpa_supp_pid'] == -1 or st['wpa_supp_pid'] == -1:
            print("Not connected")
            print('');
            continue
        else:
            if st['essid'] is None:
                print("Not connected", end='')
                print("[Wpa_sup:{}    Wpa_cli:{}]".format(
                    st['wpa_supp_pid'], st['wpa_supp_pid']))
                print('')
                continue
            else:
                print("ESSID:\"{}\"    Sinale Level:{} dbm".format(
                    st['essid'], st['signal']))
                print(fmt + "IP:{}    Gateway:{}".format(
                    st['ip'], st['gateway']))
                print('')


def _format_output_scan_result(d):
    """
    Print scan result.
    :param d: scan result dictionary as {ssid: AccessPonit}
    :return:
    """
    ssid_max_len = 0 if len(d) == 0 else len(max(d.keys(), key=len))
    line_format = "{0}     {1:17}     {2:10}     {3}"
    f = lambda x: x if len(x) >= ssid_max_len else x + ' ' * (ssid_max_len - len(x))
    print(line_format.format(f('ssid'), 'bss', 'encryption', 'signal level'))
    print(line_format.format(f('----'), '---', '----------', '------------'))
    sorted_by_signal = sorted(d.items(), key=lambda x: x[1].signal, reverse=True)
    ssid_align_max = max(ssid_max_len, len('ssid'))
    for ssid, tp in sorted_by_signal:
        print(line_format.format(ssid + ' ' * (ssid_align_max - len(ssid)),
                                 d[ssid].mac, d[ssid].encryption,
                                 str(d[ssid].signal)) + ' dbm')

class MessagePrint():
    def __init__(self):
        self.end = '\n'

    def info(self, msg, end='\n'):
        if self.end == '\n':
            print("[Info] ", end='')
            print(msg, end=end)
        else:
            print(msg, end=end)
        self.end = end

    def error(self, msg, end='\n'):
        if self.end == '\n':
            print("[Error] ", end='')
            print(msg, end=end)
        else:
            print(msg, end=end)
        self.end = end

    def quest(self, msg):
        print("[Quest] ", end='')
        return input(msg)

    def warn(self, msg):
        print("[Warn] ", end='')
        print(msg)


def _parse_args():

    import argparse
    import textwrap

    # create top parser
    parser = argparse.ArgumentParser(description=textwrap.dedent(
                                     """
                                     Wificmd, a wifi cammand tool to do wifi connection/disconnection
                                     with AP on Linux(Only works on Python3).

                                     Features:
                                        - Security on connection.
                                          Typically , Linux comes NetworkManager will switch between stored AP unexpectedly.
                                          However, if -s was specified when using \"wificmd con\", it will always try to connect
                                          with that AP. This is useful when doing some penetration work on wifi.
                                        - Support multiple wireless interface connection.
                                        - A list of core wifi function can be imported in your python code
                                          to write your owned wifi connection tool.
                                        - Networkmanager.
                                     Bugs:
                                        - Can not set the system DNS server on Ubuntu.
                                        - And maybe other bugs.
                                """),
                                     formatter_class=argparse.RawDescriptionHelpFormatter
                                     )
    # create subparser to parse sub commmand
    subparsers = parser.add_subparsers()

    parser_1 = subparsers.add_parser('scan', help='Scan for in-range AP. Use \'wificmd scan -h\' for more help')
    parser_1.add_argument('-i', dest='interface', help='If not specified, it will randomly select an available wireless interface')
    parser_1.set_defaults(func=_scan)

    parser_2 = subparsers.add_parser('stat', help='Show wificmd connection status. Use \'wificmd stat -h\' for more help')
    parser_2.add_argument('-i', dest='interface', help='If not specified, it will randomly select an available wireless interface')
    parser_2.set_defaults(func=_stat)

    parser_3 = subparsers.add_parser('con', help='Connect to added AP. Use \'wificmd con -h\' for more help')
    parser_3.add_argument('-s', '--ssid', help='If not specified, it will try to connect to any stored AP in range.')
    parser_3.add_argument('-i', dest='interface', help='If not specified, it will randomly select an available wireless interface')
    parser_3.set_defaults(func=_con)

    parser_4 = subparsers.add_parser('discon', help='Disconnect from AP. Use \'wificmd discon -h\' for more help')
    parser_4.add_argument('-i', dest='interface', help='If not specified, disconnect all wireless interface')
    parser_4.set_defaults(func=_discon)

    parser_5 = subparsers.add_parser('add', help='Save a AP profile. Use \'wificmd add -h\' for more help')
    parser_5.add_argument('ssid')
    parser_5.add_argument('-p', '--password', help='If not specified, ssid was considered as OPEN encryption.')
    parser_5.set_defaults(func=_add)

    parser_6 = subparsers.add_parser('del', help='Delete saved AP profile. Use \'wificmd del -h\' for more help')
    parser_6.add_argument('-s', '--ssid')
    parser_6.set_defaults(func=_del)

    parser_7 = subparsers.add_parser('show', help='Show saved AP profile. Use \'wificmd show -h\' for more help')
    parser_7.add_argument('-k', '--keyword', help="keyword either in ssid or password or encryption")
    parser_7.set_defaults(func=_show)

    args = parser.parse_args()
    if len(vars(args)) == 0:
        parser.print_help()
        sys.exit(-1)
    return args

_msg_print = MessagePrint()

if __name__ == '__main__':

    import sys

    # check python version
    if sys.version[0] != '3':
        print("Python3 is needed.")
        sys.exit(-1)

    # check if has root privilege
    if os.geteuid() != 0:
        _msg_print.error("Wificmd must be run as root")
        sys.exit(-1)

    # parse args and execute
    args = _parse_args()
    try:
        args.func(args)
    except NoAPProfile as e:
        _msg_print.error("No saved AP profile found.")
        _msg_print.info("Use \"wificmd con [-s ssid]\" or \"wificmd add <ssid> [-p password]\" to add an AP.")

    except ProfileNotFoundError as e:
        _msg_print.error("'%s' not found" % e.ssid)

    except CommandNotSupportedError as e:
        _msg_print.error("\"%s\" is needed but not found in your system." % e.cmd)

    except CreateFileError as e:
        _msg_print.error("Can not create file. %s" % e.err)

    except DeviceBusyError as e:
        _msg_print.error("%s was busy, try latter." % e.wface_name)

    except WPAConfigEmptyError as e:
        _msg_print.error("wpa_supplicant configuration file is empty!")

    except NotSupportedEncrytionError as e:
        _msg_print.error("Not supported Encrytion: %s" % e.enc)

    except NoWirelessInterfaceError as e:
        _msg_print.error("No wireless interface found in your device!")

    except WirelessInterfaceNotFoundError as e:
        _msg_print.error("\"%s\" not found in your device!" % e.wface_name)

    except WirelessInterfaceModeError as e:
        _msg_print.error("\"%s\" mode error.(current mode: %s)" % (e.wface_name, e.mode))

    except NoManagedWirelessInterfaceError as e:
        _msg_print.error("None of wireless interface is in Managed mode.")

    except APNotInRangeError as e:
        if e.specified:
            _msg_print.error("\"%s\" is not in range." % e.ssid_list[0])
            _msg_print.info("Dose ssid spell correctly? Use \"wificmd scan\" to view in range AP.")
        else:
            _msg_print.error("None of saved AP is in range.")

    except ProfileEncryptionError as e:
        _msg_print.error("\"%s\" encryption changed.(saved encrypiton: %s, detected encryption: %s)"
                         % (e.ssid, e.old, e.new))
        _msg_print.info("Use \"wificmd del -s <ssid>\" and \"wificmd add\" to re-add it.")

    except NotImplementedError as e:
        _msg_print.error(e)

    except KeyboardInterrupt:
        print("")
        sys.exit()
