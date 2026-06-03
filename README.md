# DHCP Spoofing - Rogue DHCP Server - Laboratorio de Seguridad de Redes

**Ambiente:** GNS3 (Controlado) | **Herramienta:** Python 3 + Scapy | **Capa OSI:** Capa 2/3/7

## Aviso Legal

Uso **exclusivamente educativo** en laboratorio controlado (GNS3). El uso no autorizado es **ilegal**.

## 1. Objetivo del Laboratorio

Demostrar como un atacante puede levantar un servidor DHCP falso (Rogue DHCP) que responda a los clientes antes que el servidor legitimo, asignandoles configuracion de red maliciosa (gateway falso, DNS falso) para facilitar ataques de MitM, redireccion de trafico o phishing.

## 2. Objetivo del Script

`dhcp_spoof.py` levanta un servidor DHCP no autorizado que:
- Escucha DHCP Discover en la red
- Responde con DHCP Offer antes que el servidor legitimo
- Asigna la IP del atacante como **gateway** (para MitM)
- Asigna un DNS malicioso opcional

## 3. Parametros del Script

| Parametro | Flag | Tipo | Default | Descripcion |
|-----------|------|------|---------|-------------|
| Interfaz | `-i` | str | eth0 | Interfaz de red |
| Gateway falso | `-g` | str | 192.168.1.254 | IP gateway a anunciar |
| DNS falso | `--dns` | str | 8.8.8.8 | Servidor DNS a anunciar |

### Ejemplo de uso

```bash
sudo python3 dhcp_spoof.py
sudo python3 dhcp_spoof.py -i eth0 -g 192.168.1.50
sudo python3 dhcp_spoof.py -g 192.168.1.50 --dns 192.168.1.50
```

## 4. Requisitos

```bash
Python 3.8+
pip install scapy
root (sudo)
```

## 5. Funcionamiento del Script

```
CLIENTE          ATACANTE (Rogue)      SERVIDOR LEGITIMO
   |                    |                       |
   |--Discover-------->|<---------Discover------|
   |                    |                       |
   |<--Offer (FALSO)---|      Offer (tarde)     |
   |                    |                       |
   |--Request--------->|                       |
   |                    |                       |
   |<--ACK (config mal)|                       |
   [Cliente usa GW/DNS malicioso del atacante]
```

## 6. Topologia de Red (GNS3)

```
 +------------------+
 | SERVIDOR DHCP    | 192.168.1.1/24 - Pool: .100-.150
 +---------+--------+
           |
 +---------+--------+
 |    SWITCH L2     |
 +-+----------+-----+
   |          |
+--+---+  +---+---------------+
|CLIENTE|  |  ATACANTE         |
| DHCP  |  |  Kali 192.168.1.50|
|(vict.)|  |  Rogue DHCP ON    |
+-------+  +-------------------+
```

### Direccionamiento IP

| Dispositivo | IP | Rol |
|-------------|-----|-----|
| Servidor DHCP legitimo | 192.168.1.1/24 | Pool: .100-.150 |
| Atacante (Kali) | 192.168.1.50/24 | Servidor Rogue |
| Cliente victima | asignada por rogue | Objetivo |

## 7. Capturas de Pantalla

Coloca tus capturas en `screenshots/`:
- `screenshots/dhcp_legit_server.png` - Servidor legitimo activo
- `screenshots/dhcp_rogue_running.png` - Script rogue ejecutandose
- `screenshots/dhcp_client_got_fake.png` - Cliente recibiendo config falsa
- `screenshots/dhcp_wireshark.png` - DORA malicioso en Wireshark

```bash
# En el cliente (Linux) - verificar configuracion recibida
ip route show && ip addr show && cat /etc/resolv.conf
# En el cliente (Windows)
ipconfig /all
```

## 8. Contramedidas

| Contramedida | Comando Cisco IOS | Descripcion |
|---|---|---|
| DHCP Snooping | `ip dhcp snooping` | Filtra mensajes DHCP en puertos no confiables |
| Puertos de confianza | `ip dhcp snooping trust` | Solo en puertos hacia servidores DHCP legitimos |
| Rate-limit DHCP | `ip dhcp snooping limit rate 15` | Limita paquetes DHCP por segundo |

```cisco
ip dhcp snooping
ip dhcp snooping vlan 1
interface GigabitEthernet0/1
 ip dhcp snooping trust
interface range GigabitEthernet0/2 - 24
 ip dhcp snooping limit rate 15
 no ip dhcp snooping trust
```

## 9. Referencias

- [MITRE ATT&CK T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [RFC 2131 - DHCP Protocol](https://datatracker.ietf.org/doc/html/rfc2131)

---
*Laboratorio de Seguridad de Redes | GNS3 | Uso educativo exclusivo*
