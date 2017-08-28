import socket
import ssl
from pprint import pprint
import json
import pickle
import subprocess
import sys
import os

INFO_FILE = "roomba.pickle"


def get_roomba_ip():
    """
    Uses nmap to scan the network for a Roomba
    :return:
    """
    tmp_file = '/tmp/net.txt'

    if os.path.exists(tmp_file):
        os.remove(tmp_file)

    print "Scanning network..."
    subprocess.call(['nmap', '-oG', tmp_file, '-sP', '192.168.1.*'], stdout=subprocess.PIPE)
    with open(tmp_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if "Roomba" in line:
                parts = line.split()
                return parts[1]

        print "#" * 80
        print "Unable to find roomba IP. Try again :)   Scan results:"
        print "#" * 80
        print "".join(lines)
        print "#" * 80


def get_roomba_blid(roomba_ip):
    """
    Gets the BLID (used later as a username) from the Roomba
    :param roomba_ip:
    :return:
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 5678))
    sock.sendto("irobotmcs", (roomba_ip, 5678))

    resp = json.loads(sock.recvfrom(1024)[0])

    return resp['hostname'].split('-')[1]


def get_roomba_password(ip):
    """
    Sends a (magic?) packet and parses the response as the password

    Mostly based on: https://github.com/koalazak/dorita980

    Thanks koalazak :)

    :param ip:
    :return:
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.SSLSocket(sock=sock)
    ssl_sock.connect((ip, 8883))

    ssl_sock.write('\xf0\x05\xef\xcc\x3b\x29\x00')

    # Should get back a 2 byte message containing the size of the next message
    r1 = [ord(x) for x in ssl_sock.recv()]

    # If we get the expected values pull out the password
    if len(r1) == 2 and r1[1] == 21:
        r2 = [chr(ord(x)) for x in ssl_sock.recv()]
        return "".join(r2[5:])

    else:
        print "ERROR make sure you pressed the button!"
        print "Got:", r1
        return ""


def read_info():
    """
    Read parameters from file
    :return:
    """
    # check for an existing file
    if os.path.exists(INFO_FILE):
        return pickle.load(open(INFO_FILE, 'r'))

    return None, None, None


def write_info(ip, blid, password):
    """
    Write the parameters to file
    :param ip:
    :param blid:
    :param password:
    :return:
    """
    new_ip = ip
    new_blid = blid
    new_pass = password

    # check for an existing file
    (old_ip, old_blid, old_pass) = read_info()

    # If still no new one, maintain the old
    if ip is None:
        new_ip = old_ip
    if blid is None:
        new_blid = old_blid
    if ip is None:
        new_pass = old_pass

    # dump the info
    pickle.dump((new_ip, new_blid, new_pass), open(INFO_FILE, 'w'))


def main():
    """
    Main program to get and save off data
    :return:
    """
    ip = get_roomba_ip()

    if ip is not None:

        blid = get_roomba_blid(ip)

        raw_input('Hold the HOME button while docked! Then press enter...')

        password = get_roomba_password(ip)

        print "IP:  ", ip
        print "BLID:", blid
        print "PASS:", password

        write_info(ip, blid, password)


if __name__ == "__main__":
    main()
