# DTP-Attack-
# DTP-Spoofing-Attack
**Network Security Tool** · Python · Scapy

> Herramienta automatizada para demostración de ataques DTP (Dynamic Trunking Protocol) en entornos de laboratorio controlados


---
# link del video: https://youtu.be/YFiki5iiexQ


---

## 📋 Tabla de Contenidos

- [Objetivo del Script](#-objetivo)
- [Características Principales](#-características-principales)
- [Capturas de Pantalla](#️-capturas-de-pantalla)
- [Topología de Red](#-topología-de-red)
- [Parámetros de Configuración](#-parámetros-de-configuración)
- [Requisitos y Uso](#-requisitos-y-uso)
- [Medidas de Mitigación](#️-medidas-de-mitigación)

---

## 🎯 Objetivo

El objetivo de este script es simular, en un entorno de laboratorio controlado, un ataque de **DTP Spoofing** (Dynamic Trunking Protocol), en el cual el atacante envía tramas DTP maliciosas para negociar un enlace trunk con el switch víctima. Al lograr convertir el puerto en modo trunk, el atacante obtiene acceso a **todas las VLANs** de la red, rompiendo la segmentación lógica e iniciando una posición de **Man-in-the-Middle** entre segmentos de red aislados.

Este proyecto tiene fines **exclusivamente educativos y de análisis de seguridad**.

**Autor:** ALEXIS JAVIER CRUZ MINYETE

---

### Reporte de Seguridad

Durante la ejecución del laboratorio se identificó que la red evaluada carece de controles básicos sobre el protocolo DTP, lo que permitió que el atacante negocie exitosamente un enlace trunk con el switch, obteniendo visibilidad sobre el tráfico de múltiples VLANs.

La ausencia de configuraciones `switchport nonegotiate`, desactivación de DTP en puertos de acceso y monitoreo de cambios de modo de puerto representa un **riesgo crítico** para la integridad de la segmentación de red.

El impacto principal del ataque es la capacidad de acceder a VLANs restringidas y capturar tráfico sensible de segmentos de red que deberían estar aislados. La implementación de controles como deshabilitar DTP globalmente, configurar puertos como access estático y aplicar VLAN Pruning reduciría considerablemente la superficie de ataque.

---

## 🖼️ Capturas de Pantalla

- **Topología de red del escenario**

<img width="1797" height="850" alt="image" src="https://github.com/user-attachments/assets/cc9475ac-b70c-4cad-ab15-2997582f04e8" />

---
- **Antes del ataque**

  <img width="1124" height="511" alt="image" src="https://github.com/user-attachments/assets/a21aa123-c05f-44f4-be86-c574da8a2f15" />


---

- **Ejecución del ataque**

  <img width="1369" height="887" alt="image" src="https://github.com/user-attachments/assets/35a5a909-782d-4665-877b-3397dfe72ecc" />


 
---
- **Puerto trunk**

<img width="1212" height="640" alt="image" src="https://github.com/user-attachments/assets/24f8e7c6-d0c7-4209-bfd6-318d455a59f0" />


---

- **Vlans visibles**

<img width="1200" height="863" alt="image" src="https://github.com/user-attachments/assets/5bfc7000-ffbf-40a8-a118-a5e38cd9f684" />


---

## 🌐 Topología de Red

> 📌 *Agregar captura de la topología de red aquí*

**Elementos de la red:**
- **Cloud My House:** Conexión a Internet
- **Kali Linux Atacante:** Máquina atacante que envía tramas DTP maliciosas
- **SW-Cloud:** Switch de conexión a cloud
- **SW-1:** Switch principal izquierdo
- **SW-2:** Switch segmento inferior izquierdo
- **SW-3:** Switch segmento derecho
- **R-SD:** Router con servidor DHCP legítimo
- **USER 1/2/3:** Clientes víctimas

---

### Tabla de Interfaces

#### Kali Linux Atacante (DTP Rogue Client)

| Interfaz | Dirección IP | Máscara | Descripción |
|----------|-------------|---------|-------------|
| eth0 | 15.0.7.2 | /24 | Interfaz principal de ataque |
| eth1 | — | — | Conexión a Cloud (opcional) |

#### R-SD (Router)

| Interfaz | Dirección IP | Máscara | Descripción |
|----------|-------------|---------|-------------|
| e0/0 | 15.0.7.1 | /24 | Red interna VLAN 20 |
| e0/1 | — | — | Conexión SW-Cloud |
| e1/0 | — | — | Conexión SW-3 |

#### SW-1 (ARISTA - Switch )

| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Access → **Trunk (post-ataque)** | Conexión Kali Atacante |
| e1/0 | Ethernet | Trunk | Uplink a Cloud |
| e0/3 | Ethernet | Access | Conexión SW-2 |

#### SW-2 (ARISTA - Switch Segmento Inferior)

| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Uplink SW-1 |
| e0/2 | Ethernet | Access | Usuario 1 |

#### SW-3 (ARISTA - Switch Segmento Derecho)

| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Uplink SW-Cloud |
| e0/2 | Ethernet | Trunk | Conexión PNET |
| e0/4 | Ethernet | Access | Usuario 2 |
| e1/0 | Ethernet | Trunk | Uplink R-SD |
| e1/1 | Ethernet | Access | Usuario 3 |

#### SW-Cloud (Switch de Acceso Cloud)

| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Downlink SW-3 |
| e0/1 | Ethernet | Trunk | Uplink Cloud My House |

#### Dispositivos Finales

| Dispositivo | Interfaz | Configuración | Switch Conectado |
|-------------|----------|---------------|-----------------|
| User 1 | eth0 | DHCP | SW-2 (e0/2) |
| User 2 | eth0 | DHCP | SW-3 (e0/4) |
| User 3 | eth0 | DHCP | SW-3 (e1/1) |

---

### VLANs Configuradas

| VLAN ID | Nombre | Segmento | Descripción |
|---------|--------|----------|-------------|
| 20 | CLIENTES | 15.0.7.0/24 | Segmento de usuarios objetivo |
| 888 | NATIVA | — | VLAN nativa para tráfico no etiquetado |
| 1 | DEFAULT | — | VLAN por defecto (no utilizada) |

---

## 🔧 Parámetros de Configuración

### Configuración del Ataque DTP

```python
# =============================================
# PARÁMETROS DEL ATAQUE DTP SPOOFING
# =============================================

interface     = "eth0"         # Interfaz de red del atacante
vlan_objetivo = 20             # VLAN objetivo a acceder
vlan_nativa   = 888            # VLAN nativa de la red
intervalo     = 0.5            # Intervalo entre tramas DTP (segundos)
modo_trunk    = "desirable"    # Modo DTP enviado (desirable / auto)
encapsulacion = "802.1Q"       # Tipo de encapsulación de trunk
```

### Tabla de Parámetros

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| Interfaz | eth0 | Interfaz física del atacante |
| VLAN Objetivo | 20 | VLAN de clientes a comprometer |
| VLAN Nativa | 888 | VLAN nativa configurada en trunk |
| Modo DTP | desirable | Modo enviado en tramas DTP maliciosas |
| Encapsulación | 802.1Q | Protocolo de etiquetado de tramas |
| Multicast DTP | 01:00:0C:CC:CC:CC | MAC destino de tramas DTP |
| Protocolo | 0x2004 | EtherType de tramas DTP |
| Intervalo | 0.5 s | Frecuencia de envío de tramas DTP |

---

## 💻 Requisitos y Uso

### Requisitos del Sistema

| Requisito | Detalle |
|-----------|---------|
| Sistema Operativo | Kali Linux / Ubuntu (con privilegios root) |
| Python | 3.8 o superior |
| Librería Scapy | 2.4.5 o superior |
| Acceso de red | Interfaz conectada al switch objetivo |
| Privilegios | root / sudo obligatorio |

### Instalación de Dependencias

```bash
pip install scapy
```

### Uso

```bash
# Clonar el repositorio
git clone https://github.com/j4vi404/DTP-Spoofing-Attack.git
cd DTP-Spoofing-Attack

# Dar permisos de ejecución
chmod +x dtp.py

# Ejecutar con privilegios root
sudo python3 dtp.py
```

### Características del Script

| Característica | Descripción |
|----------------|-------------|
| 🎯 **DTP Spoofing** | Envío de tramas DTP maliciosas para negociar trunk |
| 🔄 **Modo Desirable** | Fuerza al switch a activar modo trunk automáticamente |
| ⚡ **Respuesta rápida** | Tramas enviadas antes del timeout DTP del switch |
| ✅ **VLAN Hopping** | Acceso a todas las VLANs tras establecer el trunk |
| ✅ **Monitoreo en tiempo real** | Muestra el estado de negociación DTP |
| 📊 **Logging detallado** | Registra tramas enviadas y estado del puerto |
| 🔧 **Configuración simple** | Variables fáciles de modificar |

### Cómo Funciona

```
1. ENVÍO DE TRAMAS DTP
   └── El atacante envía tramas DTP con modo "desirable"
       hacia la MAC multicast 01:00:0C:CC:CC:CC

2. NEGOCIACIÓN DE TRUNK
   └── El switch, al recibir DTP desirable, responde
       y negocia el trunk con el atacante

3. ESTABLECIMIENTO DEL ENLACE TRUNK
   └── El puerto del switch cambia de Access → Trunk
       El atacante ahora tiene acceso a todas las VLANs

4. VLAN HOPPING
   └── El atacante puede enviar y recibir tráfico
       etiquetado con cualquier VLAN ID (1, 20, 888...)

5. MAN-IN-THE-MIDDLE
   └── Todo el tráfico de segmentos aislados puede
       ser capturado y manipulado
```

---

## 🛡️ Medidas de Mitigación

### Análisis de Riesgos y Controles — DTP Spoofing

| ID | Riesgo Identificado | Severidad | Probabilidad | Impacto | Medida de Mitigación |
|----|---------------------|-----------|--------------|---------|----------------------|
| R-001 | DTP Spoofing — Negociación de trunk maliciosa | **CRÍTICO** | Alta | Crítico | Deshabilitar DTP en todos los puertos de acceso · `switchport nonegotiate` · Configurar puertos estáticos como access |
| R-002 | VLAN Hopping — Acceso a VLANs restringidas | **CRÍTICO** | Alta | Crítico | Deshabilitar VLAN 1 como nativa · Configurar VLAN nativa dedicada · Aplicar VLAN Pruning |
| R-003 | Man-in-the-Middle entre VLANs | **CRÍTICO** | Alta | Crítico | Uso obligatorio de HTTPS/TLS · VPN para tráfico sensible · DAI (Dynamic ARP Inspection) · IDS/IPS |
| R-004 | Captura de tráfico sensible | **ALTO** | Alta | Alto | Cifrado extremo a extremo · Segmentación física en segmentos críticos · Monitoreo de tráfico anómalo |
| R-005 | Propagación del ataque a toda la red | **ALTO** | Media | Alto | Segmentación estricta de VLANs · ACLs entre segmentos · Private VLANs · Firewall interno |
| R-006 | Acceso no autorizado a VLAN administrativa | **ALTO** | Alta | Alto | VLAN de gestión dedicada y aislada · Autenticación 802.1X · Port Security con sticky MAC |
| R-007 | Falta de detección del ataque | **ALTO** | Alta | Alto | IDS/IPS (Snort, Suricata) · SIEM · Monitoreo de cambios de estado de puerto · Alertas en tiempo real |
| R-008 | Persistencia del trunk tras el ataque | **MEDIO** | Media | Alto | Verificación periódica de modos de puerto · Auditoría de configuración de switches · Notificación de cambios de modo |

---

### Controles Específicos — DTP Spoofing

#### 1. Deshabilitar DTP en Puertos de Acceso
Elimina la negociación automática de trunk en todos los puertos de usuario.

```bash
! Configurar puerto como access estático y deshabilitar DTP
Switch(config)# interface range Ethernet0/1 - 5
Switch(config-if-range)# switchport mode access
Switch(config-if-range)# switchport nonegotiate
```

#### 2. Configurar Puertos Trunk de Forma Estática
Solo los uplinks necesarios deben ser trunk, sin negociación automática.

```bash
! Configurar trunk estático en uplinks legítimos
Switch(config)# interface Ethernet1/0
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport nonegotiate
Switch(config-if)# switchport trunk allowed vlan 20,888
Switch(config-if)# switchport trunk native vlan 888
```

#### 3. VLAN Pruning y Control de VLANs Permitidas
Limitar las VLANs que viajan por cada enlace trunk.

```bash
! Permitir solo VLANs necesarias en trunks
Switch(config)# interface Ethernet1/0
Switch(config-if)# switchport trunk allowed vlan 20,888

! Eliminar VLANs no utilizadas del trunk
Switch(config-if)# switchport trunk allowed vlan remove 1-19,21-887,889-4094
```

#### 4. Port Security
Limitar direcciones MAC permitidas por puerto para evitar ataques desde dispositivos no autorizados.

```bash
SW-1(config)# interface range Ethernet0/1 - 5
SW-1(config-if-range)# switchport port-security
SW-1(config-if-range)# switchport port-security maximum 2
SW-1(config-if-range)# switchport port-security violation restrict
SW-1(config-if-range)# switchport port-security mac-address sticky
```

#### 5. Dynamic ARP Inspection (DAI)
Previene ataques ARP asociados al VLAN Hopping post-DTP.

```bash
SW-1(config)# ip arp inspection vlan 20
SW-1(config)# ip arp inspection validate src-mac dst-mac ip

! Puerto trust para gateway legítimo
SW-1(config)# interface Ethernet1/0
SW-1(config-if)# ip arp inspection trust
```
### Monitoreo y Detección

| Herramienta | Propósito | Implementación |
|-------------|-----------|----------------|
| Wireshark / tcpdump | Análisis de tramas DTP | Filtro: `dtp` o `ether proto 0x2004` |
| Snort / Suricata | IDS/IPS | Reglas para detectar DTP no autorizado |
| Syslog | Logging centralizado | Logs de cambios de modo de puerto |
| SIEM | Correlación de eventos | Alertas de puertos cambiando a trunk |
| Nagios / Zabbix | Monitoreo de red | Alertas de cambios en configuración de VLANs |
| CDP/LLDP Monitor | Detección de vecinos | Detectar dispositivos no autorizados |

---

### Plan de Respuesta a Incidentes

```
FASE 1: DETECCIÓN
├── Sistema detecta tráfico DTP no autorizado
├── Alerta automática al equipo de seguridad
├── Revisión de logs de cambios de modo de puerto
└── Identificación del puerto/dispositivo malicioso

FASE 2: CONTENCIÓN
├── Shutdown inmediato del puerto afectado
├── Aislar segmento de red comprometido
├── Preservar evidencia (capturas de tráfico)
└── Revisar qué VLANs fueron expuestas

FASE 3: ERRADICACIÓN
├── Identificar y eliminar dispositivo atacante
├── Reconfigurar puerto como access estático
├── Aplicar `switchport nonegotiate`
└── Verificar configuración de todos los trunks

FASE 4: RECUPERACIÓN
├── Restaurar configuración correcta de puertos
├── Verificar conectividad de todos los segmentos
├── Confirmar que VLANs están correctamente aisladas
└── Monitoreo intensivo durante 24-48 horas

FASE 5: LECCIONES APRENDIDAS
├── Documentar el incidente completo
├── Revisar efectividad de los controles DTP
├── Actualizar políticas de seguridad de switching
└── Capacitación al equipo técnico
```

---

## ⚠️ Disclaimer de Responsabilidad

> Este proyecto es **exclusivamente para fines educativos y de investigación** en entornos de laboratorio controlados. El uso de estas técnicas en redes sin autorización explícita es **ilegal** y puede resultar en consecuencias legales graves.
>
> El autor no se hace responsable del mal uso de esta herramienta. Al utilizar este código, aceptas usar este conocimiento de manera ética y legal.

---

*Última actualización: Febrero 2026*


                                                           *ALEXIS JAVIER CRUZ MINYETE*
                                                             ESTUDIANTES DE JONATHAN
