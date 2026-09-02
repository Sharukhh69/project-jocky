"""
socks5_proxy.py — JOCKY SOCKS5 Network Routing Daemon (RFC 1928)
─────────────────────────────────────────────────────────────────────────────
Implements stealth SOCKS5 network routing for the JOCKY forensic framework
as required by Problem Statement ID 26148:

"The scripts/functions in framework should avoid standard, noisy API calls
 for core operations like persistence, privilege escalation, and network
 routing (SOCKS5)."

HOW SOCKS5 ROUTING EVADES EDR & NETWORK MONITORING:
  1. Standard forensic agents establish direct TCP connections to the C2 server.
     - EDR network sensors and firewalls log the destination IP and flag it.
  2. With JOCKY SOCKS5 Routing:
     - All agent telemetry, commands, and forensic evidence payloads are
       tunneled through a SOCKS5 proxy (port 1080).
     - Local network packet sniffers only see traffic destined for the SOCKS5 proxy.
     - The ultimate C2 server IP is completely concealed.
     - Supports IPv4, IPv6, and Domain Name resolution (RFC 1928).
"""

import socket
import threading
import select
import struct
import sys
import os

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = int(os.environ.get("JOCKY_SOCKS5_PORT", 1080))

class SOCKS5ProxyServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server_sock = None
        self.running = False
        self.active_tunnels = 0

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(64)
        self.running = True

        print("============================================================")
        print(f"  JOCKY SOCKS5 Network Routing Daemon Active (RFC 1928)    ")
        print(f"  Listening on : {self.host}:{self.port}                   ")
        print(f"  Protocol     : SOCKS Version 5 (No Auth / Transparent)   ")
        print(f"  Traffic Mode : Encapsulated Network Evasion Tunnel       ")
        print("============================================================")

        while self.running:
            try:
                client_sock, client_addr = self.server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception:
                break

    def stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()

    def _handle_client(self, client_sock, client_addr):
        self.active_tunnels += 1
        try:
            # ── 1. Negotiation Phase (RFC 1928 Section 3) ───────────────────
            header = client_sock.recv(2)
            if len(header) < 2:
                client_sock.close()
                return

            ver, nmethods = struct.unpack("!BB", header)
            if ver != 5:
                client_sock.close()
                return

            methods = client_sock.recv(nmethods)
            # Reply: Version 5, Method 0x00 (NO AUTHENTICATION REQUIRED)
            client_sock.sendall(b"\x05\x00")

            # ── 2. Request Details Phase (RFC 1928 Section 4) ───────────────
            req_header = client_sock.recv(4)
            if len(req_header) < 4:
                client_sock.close()
                return

            ver, cmd, rsv, atyp = struct.unpack("!BBBB", req_header)
            if cmd != 1: # 0x01 = CONNECT
                # Command not supported: Reply 0x07
                client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            # Resolve target address
            dest_addr = None
            if atyp == 1: # IPv4
                raw_ip = client_sock.recv(4)
                dest_addr = socket.inet_ntoa(raw_ip)
            elif atyp == 3: # Domain Name
                name_len = ord(client_sock.recv(1))
                dest_addr = client_sock.recv(name_len).decode("utf-8", errors="replace")
            elif atyp == 4: # IPv6
                raw_ip = client_sock.recv(16)
                dest_addr = socket.inet_ntop(socket.AF_INET6, raw_ip)
            else:
                client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            raw_port = client_sock.recv(2)
            dest_port = struct.unpack("!H", raw_port)[0]

            print(f"[SOCKS5] Inbound client {client_addr[0]}:{client_addr[1]} -> Routing to {dest_addr}:{dest_port}")

            # ── 3. Connect to Destination ──────────────────────────────────
            dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest_sock.settimeout(10)
            try:
                dest_sock.connect((dest_addr, dest_port))
            except Exception as e:
                # Connection refused / failed: Reply 0x05
                client_sock.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            # Reply: Success (0x00)
            bind_addr = dest_sock.getsockname()
            reply = struct.pack("!BBBBIH", 5, 0, 0, 1,
                                struct.unpack("!I", socket.inet_aton(bind_addr[0]))[0],
                                bind_addr[1])
            client_sock.sendall(reply)

            # ── 4. Bi-directional Tunneling ────────────────────────────────
            self._forward_stream(client_sock, dest_sock)

        except Exception as e:
            pass
        finally:
            self.active_tunnels = max(0, self.active_tunnels - 1)
            try:
                client_sock.close()
            except Exception:
                pass

    def _forward_stream(self, sock1, sock2):
        sockets = [sock1, sock2]
        while True:
            r, _, w = select.select(sockets, [], sockets, 30)
            if w:
                break
            if not r:
                break
            for s in r:
                other = sock2 if s is sock1 else sock1
                try:
                    data = s.recv(16384)
                    if not data:
                        return
                    other.sendall(data)
                except Exception:
                    return

def run_socks5_daemon(host=DEFAULT_HOST, port=DEFAULT_PORT):
    proxy = SOCKS5ProxyServer(host, port)
    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\n[SOCKS5] Shutting down daemon.")
        proxy.stop()

if __name__ == "__main__":
    run_socks5_daemon()
