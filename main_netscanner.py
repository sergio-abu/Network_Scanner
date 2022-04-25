#!/usr/bin/env python

import scapy.all as scapy
import optparse
# import argparse


def get_input():
    """
    get input from user via terminal
    :return:
    """
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    options, arguments = parser.parse_args()
    return options

def scanner(ip):
    """
    network scanner
    :param ip:
    :return:
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    """
    parsing the results into a better format
    :param results_list:
    :return:
    """
    print("IP\t\t\tMAC Address\n-------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_input()
result = scanner(options.target)
print_result(result)
