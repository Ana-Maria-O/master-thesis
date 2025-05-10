from scapy.all import *

def generate_filter(filters):
    final_filter = ""

    # FPR ALL MALICIOUS PACKETS
    # Go through each filter and add it to the final filter
    for filter in filters[:-1]:
        # Add each condition in a big or statement
        final_filter += "(" + filter + ") || "
    
    # Add the last filter
    final_filter += "(" + filters[-1] + ")"

    # FOR NON-MALICIOUS PACKETS
    final_filter = "not (" + final_filter + ")"
    return final_filter
            
# Set the pcap file path
PCAP_FILE = 'mawi_00001_20240124060002.pcap'
# The list of filters for anomalies
filter_list = [
    # Suspicious
    "(ip.dst == 203.188.123.191 && tcp.dstport == 10022) || (ip.dst == 203.188.123.191)",
    "ip.src == 202.4.51.123 && tcp.dstport == 443",
    "(ip.dst == 203.188.123.167 && tcp.dstport == 80) || (ip.dst == 203.188.123.167)",
    "ip.dst == 202.4.51.25 && tcp.srcport == 443",
    "ip.src == 52.252.31.247 && ip.dst == 203.188.125.178 && tcp.srcport == 443",
    "(ip.dst == 150.162.249.131 && ip.src == 180.199.213.103) || (ip.dst == 150.162.249.131 && tcp.dstport == 80) || (ip.dst == 203.188.118.16 && ip.src == 180.199.213.103 && tcp.dstport == 80)",
    "(ip.src == 203.188.123.167 && tcp.srcport == 80) || ip.src == 203.188.123.167",
    "(ip.dst == 202.4.51.122 && tcp.srcport == 443) || (ip.dst == 202.4.51.119 && tcp.srcport == 443)",
    "((ip.dst == 202.4.51.120) && (tcp.srcport == 443))",
    "((ip.dst == 202.4.51.121) && (tcp.srcport == 443))",
    "((ip.src == 203.188.118.16) && (tcp.srcport == 80))",
    "((ip.src == 163.245.215.207) && (tcp.dstport == 443))",
    "(ip.dst == 150.162.249.131) && ((tcp.dstport == 443) || (tcp.dstport == 80))",
    "((ip.src == 203.188.123.167) && (tcp.srcport == 80)) || ip.src == 203.188.123.167",
    "ip.src == 13.29.214.170 && tcp.srcport == 443 && ip.dst == 202.4.51.119 && (tcp.dstport == 63637 || tcp.dstport == 63632 || tcp.dstport == 63628 || tcp.dstport == 63618 || tcp.dstport == 63615)",
    "ip.src == 157.140.76.186 && ((tcp.dstport == 80) || (tcp.dstport == 443 && ip.dst == 119.166.120.212))",
    "ip.src == 16.184.67.87 && ip.dst == 203.188.125.178 && tcp.srcport == 443",
    "ip.src == 52.252.31.247 && ip.dst == 203.188.125.178 && tcp.srcport == 443",
    "ip.src == 54.38.75.61 && ip.dst == 203.188.125.178 && tcp.srcport == 443",
    "ip.src == 54.38.54.184 && ip.dst == 203.188.125.178 && tcp.srcport == 443",
    "((ip.src == 150.162.249.131) && (tcp.srcport == 80)) || ((ip.src == 150.162.249.131) && (tcp.srcport == 443)) || ((ip.src == 203.188.123.167) && (tcp.srcport == 80))",
    "(ip.src == 157.140.162.184) && (ip.dst == 3.22.106.199) && (tcp.dstport == 443)",
    "(ip.src == 203.188.123.167 && tcp.srcport == 80) || (ip.dst == 203.188.123.167)",
    "ip.src == 202.4.51.61 && ip.dst == 52.226.52.236 && tcp.dstport == 443",

    # Anomalous
    "(ip.src == 150.162.249.131 && (tcp.srcport == 80 || tcp.srcport == 443)) || (ip.src == 203.188.123.167 && tcp.srcport == 80)",
    "ip.src == 157.140.162.184 && ip.dst == 3.22.106.199 && tcp.dstport == 443",
    "frame.time_epoch >= 1706072400 && ((ip.dst == 203.188.125.160 && tcp.dstport == 26190) || (ip.dst == 203.188.125.160))",
    "(ip.dst == 131.62.216.24)",
    "((ip.src == 203.188.125.160) || ((ip.src == 203.188.125.160) && (tcp.srcport == 26190))) && frame.time_epoch >= 1706072400",
    "(ip.src == 202.4.51.61) && (ip.dst == 18.69.105.227) && (tcp.dstport == 443)",
    "((ip.dst == 203.188.123.191) && (tcp.dstport == 10022)) || (ip.dst == 203.188.123.191)",
    "(ip.src == 131.62.216.24) && (((ip.dst == 94.125.246.135) && (tcp.srcport == 4500) && (tcp.dstport == 4980)) || ((ip.dst == 157.130.102.190) && (tcp.srcport ==60000) && (tcp.dstport == 443)) || ((ip.dst == 192.50.25.191) && (tcp.srcport == 587) && (tcp.dstport == 33083)) || ((ip.dst == 162.255.241.29) && (tcp.srcport == 587) && (tcp.dstport == 50688)))",
    "((ip.src == 203.188.123.191) && (tcp.srcport == 10022)) || (ip.src == 203.188.123.191)"
]

filter_list_real = [
    # Suspicious
    "(ip.dst == 203.188.123.191 && (tcp.dstport == 10022 || udp.dstport == 10022)) || (ip.dst == 203.188.123.191)",
    "ip.src == 202.4.51.123 && (tcp.dstport == 443 || udp.dstport == 443)",
    "(ip.dst == 203.188.123.167 && (tcp.dstport == 80 || udp.dstport == 80)) || (ip.dst == 203.188.123.167)",
    "ip.dst == 202.4.51.25 && (tcp.srcport == 443 || udp.srcport == 443)",
    "ip.src == 52.252.31.247 && ip.dst == 203.188.125.178 && (tcp.srcport == 443 || udp.srcport == 443)", # Not in the set
    "(ip.dst == 150.162.249.131 && ip.src == 180.199.213.103) || (ip.dst == 150.162.249.131 && (tcp.dstport == 80 || udp.dstport == 80)) || (ip.dst == 203.188.118.16 && ip.src == 180.199.213.103 && (tcp.dstport == 80 || udp.dstport == 80))",
    "(ip.src == 203.188.123.167 && (tcp.srcport == 80 || udp.srcport == 80)) || ip.src == 203.188.123.167",
    "(ip.dst == 202.4.51.122 && (tcp.srcport == 443 || udp.srcport == 443)) || (ip.dst == 202.4.51.119 && (tcp.srcport == 443 || udp.srcport == 443))",
    "(ip.dst == 202.4.51.120) && (tcp.srcport == 443 || udp.srcport == 443)",
    "ip.dst == 202.4.51.121 && (tcp.srcport == 443 || udp.srcport == 443)",
    "ip.src == 203.188.118.16 && (tcp.srcport == 80 || udp.srcport == 80)",
    "(ip.src == 163.245.215.207) && (tcp.dstport == 443 || udp.dstport == 443)",
    "ip.src == 13.29.214.170 && (tcp.srcport == 443 || udp.srcport == 443) && ip.dst == 202.4.51.119 && (tcp.dstport == 63637 || tcp.dstport == 63632 || tcp.dstport == 63628 || tcp.dstport == 63618 || tcp.dstport == 63615 || udp.dstport == 63637 || udp.dstport == 63632 || udp.dstport == 63628 || udp.dstport == 63618 || udp.dstport == 63615)", # None in the set
    "ip.src == 157.140.76.186 && ((tcp.dstport == 80 || udp.dstport == 80) || ((tcp.dstport == 443 || udp.dstport == 443) && ip.dst == 119.166.120.212))",
    "ip.src == 16.184.67.87 && ip.dst == 203.188.125.178 && (tcp.srcport == 443 || udp.srcport == 443)", # Not in set
    "ip.src == 52.252.31.247 && ip.dst == 203.188.125.178 && (tcp.srcport == 443 || udp.srcport == 443)", # Not in set
    "ip.src == 54.38.75.61 && ip.dst == 203.188.125.178 && (tcp.srcport == 443 || udp.srcport == 443)", # Not in set
    "ip.src == 54.38.54.184 && ip.dst == 203.188.125.178 && (tcp.srcport == 443 || udp.srcport == 443)", # Not in set
    "(ip.dst == 150.162.249.131) && ((tcp.dstport == 443 || udp.dstport == 443) || (tcp.dstport == 80 || udp.dstport == 80))",
    "((ip.src == 203.188.123.167) && (tcp.srcport == 80 || udp.srcport == 80)) || ip.src == 203.188.123.167",
    "ip.src == 202.4.51.61 && ip.dst == 52.226.52.236 && (tcp.dstport == 443 || udp.dstport == 443)", # Not in set

    "(ip.src == 203.188.123.167 && (tcp.srcport == 80 || udp.srcport == 80)) || (ip.dst == 203.188.123.167)",

    # Anomalous
    "(ip.src == 150.162.249.131 && (tcp.srcport == 80 || tcp.srcport == 443 || udp.srcport == 443 || udp.srcport == 80)) || (ip.src == 203.188.123.167 && (tcp.srcport == 80 || udp.srcport == 80))",
    "ip.src == 157.140.162.184 && ip.dst == 3.22.106.199 && (tcp.dstport == 443 || udp.dstport == 443)",
    "frame.time_epoch >= 1706072400 && ((ip.dst == 203.188.125.160 && (tcp.dstport == 26190 || udp.dstport == 26190)) || (ip.dst == 203.188.125.160))",
    "(ip.dst == 131.62.216.24)", # Not in the set
    "((ip.src == 203.188.125.160) || ((ip.src == 203.188.125.160) && (tcp.srcport == 26190 || udp.srcport == 26190))) && frame.time_epoch >= 1706072400",
    "(ip.src == 202.4.51.61) && (ip.dst == 18.69.105.227) && (tcp.dstport == 443 || udp.dstport == 443)",
    "((ip.dst == 203.188.123.191) && (tcp.dstport == 10022 || udp.dstport == 10022)) || (ip.dst == 203.188.123.191)",
    "(ip.src == 131.62.216.24) && (((ip.dst == 94.125.246.135) && (tcp.srcport == 4500 || udp.srcport == 4500) && (tcp.dstport == 4980 || udp.dstport == 4980)) || ((ip.dst == 157.130.102.190) && (tcp.srcport == 60000 || udp.srcport == 60000) && (tcp.dstport == 443 || udp.dstport == 443)) || ((ip.dst == 192.50.25.191) && (tcp.srcport == 587 || udp.srcport == 587) && (tcp.dstport == 33083 || udp.dstport == 33083)) || ((ip.dst == 162.255.241.29) && (tcp.srcport == 587 || udp.srcport == 587) && (tcp.dstport == 50688 || udp.dstport == 50688)))", # Not in the set
    "((ip.src == 203.188.123.191) && (tcp.srcport == 10022 || udp.srcport == 10022)) || (ip.src == 203.188.123.191)"
]

# Set the filter criteria
FILTER = generate_filter(filter_list_real)
# udp = FILTER.replace("tcp", "udp")
# tcp_filter = open("tcp_filter.txt", "w")
tcp_filter = open("udp_filter.txt", "w")
tcp_filter.write(FILTER)
# udp_filter = open("udp_filter.txt", "w")
