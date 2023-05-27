import socket
import scapy.all as scapy

MASK = '/24'

ips = socket.gethostbyname_ex(socket.gethostname())[-1]
for ip in ips:
    arp = scapy.ARP(pdst=ip+MASK)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = scapy.srp(packet, timeout=3, verbose=0)[0]
    if len(result) == 0:
        continue

    print(f'{"":20}{"IP:":20}{"MAC:":20}{"Name:"}')

    clients = []
    for sent, received in result:
        try:
            name = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            name = '-'

        if received.psrc == ip:
            print(f'{"Your device:":20}{ip:20}{received.hwsrc:20}{name}')
            continue

        clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'name': name})

    first = True
    for client in clients:
        if first:
            print(f'{"Other devices:":20}{client["ip"]:20}{client["mac"]:20}{client["name"]}')
            first = False
        else:
            print(f'{"":20}{client["ip"]:20}{client["mac"]:20}{client["name"]}')
