"""
Firewall service for Cachy Security Suite.
Provides high-level management for UFW (Uncomplicated Firewall) and netfilter,
including non-root passive status inspection, rule parsing, security profiles,
polkit-authenticated actions (enable/disable, add/delete rules), and live block logs.
"""

import os
import re
import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class FirewallRule:
    action: str = "ALLOW"             # ALLOW, DENY, REJECT, LIMIT
    direction: str = "Eingehend"      # Eingehend (in), Ausgehend (out)
    proto: str = "ANY"                # TCP, UDP, ANY
    dport: str = "any"                # Port or range, e.g. 22 or 1714:1764
    sport: str = "any"
    src_ip: str = "any"               # e.g. 0.0.0.0/0 or 192.168.1.0/24
    dst_ip: str = "any"
    comment: str = ""
    is_v6: bool = False
    raw_tuple: str = ""

    def display_port(self) -> str:
        if self.dport in ("any", "0:0", "0"):
            return "Alle Ports"
        return self.dport

    def display_source(self) -> str:
        if self.src_ip in ("0.0.0.0/0", "::/0", "any"):
            return "Überall (Alle IPs)"
        return self.src_ip


@dataclass
class BlockedPacket:
    time_str: str
    interface: str
    src_ip: str
    dst_ip: str
    proto: str
    spt: str
    dpt: str
    raw: str


@dataclass
class FirewallStatus:
    installed: bool = False
    enabled: bool = False
    service_active: bool = False
    service_enabled: bool = False
    default_incoming: str = "DROP (Blockieren)"
    default_outgoing: str = "ACCEPT (Erlauben)"
    default_forward: str = "DROP (Blockieren)"
    rules_count: int = 0
    backend_name: str = "UFW (Uncomplicated Firewall)"
    details: str = ""


class FirewallService:
    """Manages system firewall interaction and rule generation."""

    @staticmethod
    def is_installed() -> bool:
        return shutil.which("ufw") is not None

    @classmethod
    def get_status(cls) -> FirewallStatus:
        status = FirewallStatus()
        status.installed = cls.is_installed()
        if not status.installed:
            status.details = "UFW ist auf diesem System nicht installiert."
            return status

        # 1. Check /etc/ufw/ufw.conf (readable without root)
        ufw_conf = "/etc/ufw/ufw.conf"
        if os.path.exists(ufw_conf):
            try:
                with open(ufw_conf, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ENABLED="):
                            val = line.split("=", 1)[1].strip().lower()
                            status.enabled = val in ("yes", "1", "true")
            except Exception:
                pass

        # 2. Check systemd service status
        try:
            res_act = subprocess.run(["systemctl", "is-active", "ufw.service"], capture_output=True, text=True, check=False)
            status.service_active = res_act.stdout.strip() == "active"
            res_en = subprocess.run(["systemctl", "is-enabled", "ufw.service"], capture_output=True, text=True, check=False)
            status.service_enabled = res_en.stdout.strip() == "enabled"
        except Exception:
            pass

        # 3. Check default policies in /etc/default/ufw
        def_ufw = "/etc/default/ufw"
        if os.path.exists(def_ufw):
            try:
                with open(def_ufw, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("DEFAULT_INPUT_POLICY="):
                            val = line.split("=", 1)[1].replace('"', "").replace("'", "").strip()
                            status.default_incoming = "ACCEPT (Erlauben)" if "ACCEPT" in val.upper() else "DROP (Blockieren)"
                        elif line.startswith("DEFAULT_OUTPUT_POLICY="):
                            val = line.split("=", 1)[1].replace('"', "").replace("'", "").strip()
                            status.default_outgoing = "ACCEPT (Erlauben)" if "ACCEPT" in val.upper() else "DROP (Blockieren)"
                        elif line.startswith("DEFAULT_FORWARD_POLICY="):
                            val = line.split("=", 1)[1].replace('"', "").replace("'", "").strip()
                            status.default_forward = "ACCEPT (Erlauben)" if "ACCEPT" in val.upper() else "DROP (Blockieren)"
            except Exception:
                pass

        # 4. Count rules
        rules = cls.get_rules()
        status.rules_count = len(rules)
        return status

    @classmethod
    def get_rules(cls) -> List[FirewallRule]:
        """Parses active user rules from /etc/ufw/user.rules and /etc/ufw/user6.rules."""
        rules: List[FirewallRule] = []
        paths = [
            ("/etc/ufw/user.rules", False),
            ("/etc/ufw/user6.rules", True),
        ]

        seen_keys = set()

        for filepath, is_v6 in paths:
            if not os.path.exists(filepath):
                continue
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("### tuple ###"):
                            # Format: ### tuple ### action proto dport dst_ip sport src_ip comment - direction
                            parts = line.split()
                            if len(parts) >= 12:
                                action = parts[3].upper()
                                proto = parts[4].upper()
                                dport = parts[5]
                                dst_ip = parts[6]
                                sport = parts[7]
                                src_ip = parts[8]
                                raw_comment = parts[9]
                                comment = urllib.parse.unquote(raw_comment) if raw_comment != "none" else ""
                                if comment.startswith("dapp_"):
                                    comment = comment[5:]
                                direction_code = parts[11].lower()
                                direction = "Eingehend" if direction_code == "in" else "Ausgehend"

                                # Deduplicate between v4 and v6 if they share same rule definition
                                key = (action, proto, dport, direction, comment, src_ip)
                                if key in seen_keys:
                                    continue
                                seen_keys.add(key)

                                rules.append(FirewallRule(
                                    action=action,
                                    direction=direction,
                                    proto=proto,
                                    dport=dport,
                                    sport=sport,
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    comment=comment,
                                    is_v6=is_v6,
                                    raw_tuple=line
                                ))
            except Exception:
                pass

        return rules

    @classmethod
    def get_blocked_packets(cls, limit: int = 50) -> List[BlockedPacket]:
        """Reads recent blocked packets from systemd kernel journal."""
        packets: List[BlockedPacket] = []
        try:
            cmd = ["journalctl", "-k", "-g", "UFW BLOCK", "-n", str(limit), "--no-pager"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.strip().split("\n"):
                    if "[UFW BLOCK]" not in line:
                        continue
                    # Parse timestamp (e.g. Sep 15 19:15:14)
                    time_match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)", line)
                    time_str = time_match.group(1) if time_match else "-"

                    in_match = re.search(r"IN=([^\s]+)", line)
                    interface = in_match.group(1) if in_match else "unknown"

                    src_match = re.search(r"SRC=([^\s]+)", line)
                    src_ip = src_match.group(1) if src_match else "-"

                    dst_match = re.search(r"DST=([^\s]+)", line)
                    dst_ip = dst_match.group(1) if dst_match else "-"

                    proto_match = re.search(r"PROTO=([^\s]+)", line)
                    proto = proto_match.group(1) if proto_match else "TCP"

                    spt_match = re.search(r"SPT=(\d+)", line)
                    spt = spt_match.group(1) if spt_match else "-"

                    dpt_match = re.search(r"DPT=(\d+)", line)
                    dpt = dpt_match.group(1) if dpt_match else "-"

                    packets.append(BlockedPacket(
                        time_str=time_str,
                        interface=interface,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        proto=proto,
                        spt=spt,
                        dpt=dpt,
                        raw=line
                    ))
        except Exception:
            pass

        packets.reverse()  # Show most recent first
        return packets

    @classmethod
    def get_app_profiles(cls) -> List[Dict[str, str]]:
        """Parses common application profiles from /etc/ufw/applications.d/."""
        profiles = [
            {"id": "ssh", "title": "SSH (Secure Shell)", "port": "22", "proto": "TCP", "desc": "Sicherer Fernzugriff auf die Konsole"},
            {"id": "kdeconnect", "title": "KDE Connect", "port": "1714:1764", "proto": "ANY", "desc": "Smartphone-Integration (Fotos, Benachrichtigungen, Zwischenablage)"},
            {"id": "http", "title": "Webserver (HTTP)", "port": "80", "proto": "TCP", "desc": "Lokaler unverschlüsselter Webserver"},
            {"id": "https", "title": "Sicherer Webserver (HTTPS)", "port": "443", "proto": "TCP", "desc": "Lokaler SSL/TLS Webserver"},
            {"id": "samba", "title": "Samba Windows-Dateifreigabe", "port": "445", "proto": "TCP", "desc": "Netzwerkfreigaben für Windows und Linux"},
            {"id": "steam", "title": "Steam & Gaming", "port": "27015:27050", "proto": "UDP", "desc": "Multiplayer-Spiele und Server-Browsing"},
            {"id": "wireguard", "title": "WireGuard VPN", "port": "51820", "proto": "UDP", "desc": "Sicheres VPN-Tunnelnetzwerk"},
            {"id": "dns", "title": "DNS-Dienst", "port": "53", "proto": "ANY", "desc": "Lokale Namensauflösung (Pi-hole / dnsmasq)"},
            {"id": "localsend", "title": "LocalSend", "port": "53317", "proto": "ANY", "desc": "Lokaler Dateiübertragungsdienst"},
        ]
        return profiles

    # --------------------------------------------------------------------------
    # Privileged Actions via Polkit (pkexec)
    # --------------------------------------------------------------------------

    @classmethod
    def _run_privileged(cls, args: List[str]) -> Tuple[bool, str]:
        """Runs command using pkexec (or sudo fallback if in terminal)."""
        cmd = []
        if os.geteuid() != 0:
            if shutil.which("pkexec"):
                cmd.append("pkexec")
            elif shutil.which("sudo"):
                cmd.append("sudo")
        cmd.extend(args)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = (res.stdout + "\n" + res.stderr).strip()
            if res.returncode == 0:
                return True, output
            return False, output or f"Befehl schlug fehl mit Code {res.returncode}"
        except Exception as e:
            return False, f"Fehler bei Ausführung: {str(e)}"

    @classmethod
    def set_enabled(cls, enable: bool) -> Tuple[bool, str]:
        """Enables or disables UFW and ensures systemd service state."""
        action = "enable" if enable else "disable"
        ok, msg = cls._run_privileged(["ufw", "--force", action])
        if ok and enable:
            # Also ensure systemctl ufw.service is active
            cls._run_privileged(["systemctl", "enable", "--now", "ufw.service"])
        return ok, msg

    @classmethod
    def apply_profile(cls, profile_name: str) -> Tuple[bool, str]:
        """
        Applies a predefined security policy profile:
        - 'home': Incoming DROP, Outgoing ACCEPT
        - 'public_wifi': Incoming DROP, Outgoing ACCEPT, Logging HIGH
        - 'lockdown': Incoming DROP, Outgoing DROP
        """
        if profile_name == "home":
            ok1, m1 = cls._run_privileged(["ufw", "default", "deny", "incoming"])
            ok2, m2 = cls._run_privileged(["ufw", "default", "allow", "outgoing"])
            cls._run_privileged(["ufw", "logging", "low"])
            return (ok1 and ok2), f"{m1}\n{m2}".strip()

        elif profile_name == "public_wifi":
            ok1, m1 = cls._run_privileged(["ufw", "default", "deny", "incoming"])
            ok2, m2 = cls._run_privileged(["ufw", "default", "allow", "outgoing"])
            cls._run_privileged(["ufw", "logging", "high"])
            return (ok1 and ok2), f"Profil Öffentliches WLAN aktiviert:\n{m1}".strip()

        elif profile_name == "lockdown":
            ok1, m1 = cls._run_privileged(["ufw", "default", "deny", "incoming"])
            ok2, m2 = cls._run_privileged(["ufw", "default", "deny", "outgoing"])
            cls._run_privileged(["ufw", "logging", "medium"])
            return (ok1 and ok2), f"Sicherheits-Lockdown aktiviert (Alle Verbindungen blockiert):\n{m1}\n{m2}".strip()

        return False, f"Unbekanntes Profil: {profile_name}"

    @classmethod
    def add_rule(
        cls,
        action: str = "allow",
        direction: str = "in",
        proto: str = "any",
        port: str = "",
        src_ip: str = "any",
        comment: str = ""
    ) -> Tuple[bool, str]:
        """Adds a firewall rule using ufw."""
        action_clean = action.lower()
        if action_clean not in ("allow", "deny", "reject", "limit"):
            action_clean = "allow"

        cmd = ["ufw", action_clean]

        if direction.lower() in ("in", "eingehend"):
            cmd.append("in")
        elif direction.lower() in ("out", "ausgehend"):
            cmd.append("out")

        # Source IP
        src_clean = src_ip.strip()
        if src_clean and src_clean.lower() not in ("any", "überall", "0.0.0.0/0"):
            cmd.extend(["from", src_clean])

        # Destination Port & Protocol
        port_clean = port.strip()
        proto_clean = proto.strip().lower()

        if port_clean and port_clean != "any":
            cmd.extend(["to", "any", "port", port_clean])
            if proto_clean in ("tcp", "udp"):
                cmd.extend(["proto", proto_clean])
        elif proto_clean in ("tcp", "udp"):
            cmd.extend(["proto", proto_clean])

        if comment.strip():
            cmd.extend(["comment", comment.strip()])

        return cls._run_privileged(cmd)

    @classmethod
    def delete_rule(cls, rule: FirewallRule) -> Tuple[bool, str]:
        """Deletes a rule by matching its parameters."""
        action_clean = rule.action.lower()
        cmd = ["ufw", "delete", action_clean]

        if rule.direction.lower() in ("out", "ausgehend"):
            cmd.append("out")

        port = rule.dport
        proto = rule.proto.lower()

        if rule.src_ip not in ("0.0.0.0/0", "::/0", "any", ""):
            cmd.extend(["from", rule.src_ip])

        if port not in ("any", "0:0", "0", ""):
            cmd.extend(["to", "any", "port", port])
            if proto in ("tcp", "udp"):
                cmd.extend(["proto", proto])
        elif proto in ("tcp", "udp"):
            cmd.extend(["proto", proto])

        if rule.comment:
            cmd_with_comment = list(cmd) + ["comment", rule.comment]
            ok, out = cls._run_privileged(cmd_with_comment)
            if ok:
                return ok, out

        return cls._run_privileged(cmd)
