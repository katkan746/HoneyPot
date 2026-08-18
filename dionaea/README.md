# SMB and Database Honeypot Analysis — What Arrives When You Leave File Sharing Open

This report covers the Dionaea sensor from the same T-Pot honeypot described in
the [repository README](../README.md). Where [`cowrie/`](../cowrie/) asks how
many separate attackers are behind the SSH and Telnet traffic, this report asks
a different question: **what actually gets deposited on an exposed Windows file
share, and can the sensor tell you who deposited it?**

The short answer to the first half is: one thing, over and over. Dionaea
captured 55 malware samples, and every one of them is the same WannaCry dropper
chain — a worm that has been propagating unattended since 2017. The short
answer to the second half is: no. The readable Dionaea logs record connections
but not captures, so the samples on disk cannot be tied to the addresses that
sent them.

**A note on coverage before anything else.** This analysis rests on roughly
thirteen hours of readable log data from 17 August, not the full five-day
window. The reasons are set out in [Read this before the
numbers](#read-this-before-the-numbers), and every figure below is scoped
accordingly. Numbers quoted from the T-Pot dashboard are labelled as such and
have **not** been independently reproduced.

---

## Executive summary

This section is written for readers who do not work in security. The rest of
the report assumes technical knowledge.

**What was done.** One machine was connected to the internet and left to be
attacked. It pretended to offer ordinary business services — Windows file
sharing, databases, file transfer — and recorded what was sent to it. This
report covers the part of the machine that imitates those services.

**What arrived.** Two thirds of the connections went to a single service:
Windows file sharing, the mechanism that lets office computers share folders
with each other. It is not supposed to be reachable from the internet at all.
Every one of the 55 malware samples collected came in through it.

**The main finding.** All 55 samples are the same thing: WannaCry, the
ransomware worm that spread worldwide in May 2017. Nine years on it is still
circulating, not because anyone is running a campaign, but because infected
machines that were never cleaned up keep scanning the internet and infecting
each other. What the honeypot recorded is not an attack aimed at it. It is
background noise from an epidemic that was never fully cleared.

**Why that matters.** WannaCry spreads through a flaw that Microsoft patched in
March 2017. Any machine still catching it has been unpatched for nine years.
The practical lesson is unglamorous and worth repeating: file sharing should
never be exposed to the internet, and a patch released in 2017 should have been
applied in 2017.

Three further points are worth drawing out:

- **The sensor cannot say who sent the malware.** It logs connections in one
  place and captured files in another, and the readable logs contain no field
  linking the two. The 55 files exist; the addresses that delivered them do
  not survive in any data that could be read here. This is a limitation of what
  was recoverable, not a claim about the sensor's design.
- **Three addresses behaved identically.** Three unrelated addresses each made
  exactly 33 connections to file sharing. Identical totals across supposedly
  independent hosts do not happen by chance — the same pattern the SSH report
  found, appearing again on a different service.
- **One scanner leaked the honeypot's own address back to it.** A file-transfer
  probe echoed the machine's public address in its command. That address has
  been removed from this report and from every file in this repository, as the
  repository scope requires.

**What this report cannot tell you.** Most of the five-day window could not be
read. The compressed log archives and the sensor's database file both need
tooling that was unavailable on the analysis machine, so this covers about
thirteen hours of one day. Treat it as a core sample, not a survey.

### Attack volume by sensor

![Bar chart of attacks recorded by each honeypot sensor between 13 and 17 August 2026. Honeytrap 303k, Cowrie 243k, RDPHoneypot 153k, Sentrypeer 36k, Dionaea 14k, Honeyaml 5k, Tanner 2k, ConPot 2k, Heralding 1k and H0neytr4p 1k, from a total of 762k.](../docs/images/honeypot-attacks-by-sensor.svg)

*Attacks recorded by each sensor over the five-day window, taken from the T-Pot
dashboard totals. Dionaea, fifth of the ten, is the source for this report.*

---

## Observation window

**Nominal window: 13–17 August 2026.** That is the window for the 14,000-event
dashboard figure quoted in the repository README.

**Window actually analysed here: 2026-08-17T01:55:20Z to 2026-08-17T15:06:09Z.**
One calendar day, thirteen hours and eleven minutes, verified as the earliest
and latest timestamps in the readable log.

The gap is not a sampling choice. It is what could be read. See below.

---

## Read this before the numbers

**This analysis covers 990 events. The dashboard figure for the window is
14,000. These two numbers have not been reconciled, and this report does not
attempt to reconcile them.**

The readable data is a single uncompressed log, `dionaea.json`, holding exactly
990 connection records, all dated 17 August. Everything else is unreadable
without tooling the analysis machine did not have:

| Artefact | Status | What it would have given |
|---|---|---|
| `dionaea.json` | **readable — 990 events** | connections for 17 Aug only |
| `dionaea.json.1` – `.5` (gzip) | unreadable | 13–16 Aug connections |
| `dionaea.sqlite` (+ 5 gzip rotations) | unreadable | **sample-to-source-IP attribution** |
| `binaries.tgz` (+ rotations) | unreadable | earlier captured samples |
| `bistreams.tgz` (+ rotations) | unreadable | earlier connection streams |
| `binaries/` (live directory) | **readable — 55 files** | the samples analysed here |
| `bistreams/2026-08-17/` | **readable — 739 stream files** | 17 Aug streams, corroborating counts |

990 events is **7.1%** of the 14,000 figure. That ratio is plausible for
thirteen hours out of five days, but plausibility is not reconciliation: the
dashboard counts Elasticsearch documents and this log counts written lines, and
the two need not use the same denominator. **No claim in this report should be
read as characterising the full 14,000.** Where a proportion is given, it is a
proportion of the 990.

The 55 samples are a partial exception. They sit in the live `binaries/`
directory rather than a rotated archive, and rotated `binaries.tgz` files exist
alongside them, so 55 is the count that survived to analysis rather than the
count ever captured. It is also **not verifiable that all 55 fall inside the
17 August window** — file timestamps could not be read.

One further caveat inherited throughout: **no hashing tool was available.**
Dionaea names captured files by their MD5. Those names are reproduced here as
recorded by the sensor; none was independently recomputed, so no
filename-versus-content check was possible.

---

## Finding 1 — Two thirds of the traffic is Windows file sharing

Of 990 connection events, 675 went to SMB on port 445.

| Service | Port | Events | Share |
|---|---|---|---|
| `smbd` | 445 | 675 | 68.2% |
| `pptpd` | 1723 | 114 | 11.5% |
| `mongod` | 27017 | 77 | 7.8% |
| `mssqld` | 1433 | 51 | 5.2% |
| `mysqld` | 3306 | 33 | 3.3% |
| `httpd` | 81 | 17 | 1.7% |
| `ftpd` | 21 | 14 | 1.4% |
| `epmapper` | 135 | 5 | 0.5% |
| `mqttd` | 1883 | 3 | 0.3% |
| `ftpdatalisten` | ephemeral | 1 | 0.1% |
| **Total** | | **990** | |

All connections are TCP. 989 are `accept` events; the single `ftpdatalisten`
entry is the sensor opening its own FTP data channel, not an inbound
connection.

The 739 stream files captured on 17 August corroborate the shape
independently: 470 SMB, 113 PPTP, 80 MongoDB, 6 MSSQL, the remainder spread
across the smaller services.

Two observations worth recording. First, the repository's Contents table
describes Dionaea as "SMB, FTP, MySQL, MSSQL"; in practice the sensor also
fielded meaningful volumes of **PPTP, MongoDB, HTTP, MQTT and DCE/RPC endpoint
mapper** traffic, and PPTP and MongoDB together outrank every service in that
list except SMB. Second, exactly **one** source address in the whole log is
private — `172.23.0.1`, the Docker bridge gateway, appearing once. It is
excluded from every table and CSV here, following the convention set in
[`../cowrie/indicators/README.md`](../cowrie/indicators/README.md). The
practical impact is negligible at 0.1%, unlike some honeypot datasets where
container noise dominates.

---

## Finding 2 — All 55 captured samples are the same 2017 worm

Every file in the `binaries/` directory begins with `MZ`, the Windows
executable signature. There are no Linux binaries, no scripts, and no archives.
All 55 are the WannaCry dropper chain.

**Structure.** An outer executable exports a function called `PlayGame` from a
component named `launcher.dll`, and imports the Windows resource and process
APIs. It carries the drop filename `mssecsvc.exe` and the path format string
`C:\%s\%s`. Inside it sits a second executable whose oversized resource section
holds a password-protected ZIP archive containing the ransomware payload —
`tasksche.exe`, `@WanaDecryptor@`, `taskdl.exe`, `taskse.exe`.

**Marker distribution**, measured by searching each of the 55 files
individually:

| Marker | Present | Note |
|---|---:|---|
| `launcher.dll` | **55 / 55** | outer loader export |
| `PlayGame` | **55 / 55** | outer loader export |
| `OpenSCManagerA` | **55 / 55** | generic Windows API |
| `WININET.dll` | **55 / 55** | generic Windows API |
| `WNcry@2ol7` | 48 / 55 | ZIP password for the payload |
| `CryptEncrypt` | 48 / 55 | |
| `CryptDestroyKey` | 48 / 55 | |
| kill-switch domain | 22 / 55 | |

**Two sub-clusters.** 48 files carry the complete marker set. Seven do not, and
they are the *same* seven files in each case:

```
dd0f515ed8fd732bbbdf78db2f93c2c6    9a936a0b3b66b6ad153f1a59426da531
5630a1e4d520ff06dd5e20a95101ab05    a21f7847f4edfb503107c343fcdf5ab6
66bb0b650bfdf95d6000f97d4bbf0f25    1d7be28d97a57aeaeca8e9b96057a526
37c07aa4965f5f1bd40600ea762a040f
```

All seven retain every marker that sits near the *start* of the file and lose
only markers buried deep in the embedded payload. But they do **not** all look
alike, and the difference matters:

| Sub-group | Files | ZIP record headers | Reading |
|---|---|---|---|
| Truncated | `5630a1e4…`, `1d7be28d…`, `37c07aa4…` | 16, 9, 8 | archive region cut short |
| Archive intact | `dd0f515e…`, `66bb0b65…`, `9a936a0b…`, `a21f7847…` | 30–32 | archive present, password absent |

Complete files carry 30–32 ZIP records. So only three of the seven show the
record-count drop that truncation would produce. **The other four carry an
apparently intact payload archive while still missing the ZIP password and the
crypto API strings** — which truncation does not explain, because those files
are not short of archive content.

**This is where the evidence runs out.** Distinguishing a truncated capture
from a genuine variant build needs exact byte sizes and a hex comparison, and
file sizes could not be read precisely — the only size signal available rounds
every file to "5MB". `a21f7847…` complicates it further by keeping
`mssecsvc.exe` and a full `OpenSCManagerA` count while still lacking the crypto
markers.

So: three files are *probably truncated*; four are *unexplained* and a variant
build cannot be ruled out for them. The ZIP record counts come from an earlier
reading pass and **could not be independently re-verified** with the tooling
available, since counting binary record markers needs offset-aware search. They
are reported as the weakest figures in this analysis.

A related oddity: `1d7be28d…` carries the kill-switch domain but **not** the
ZIP password, so the two marker sets are not nested and neither implies the
other.

### Re-measuring the existing YARA rule against the surviving corpus

The repository's `yara/wannacry.yara` requires the string `WNcry@2ol7` before
anything else can match. Seven of these 55 files do not contain it.

- **Measured coverage on the corpus as it stands today: 48 / 55, or 87.3%.**
  The seven are guaranteed misses.
- The rule's metadata records `true_positives = "65/65"` against "65 Dionaea
  SMB captures, 5267459 bytes each". **This is not evidence that the metadata
  was wrong.** The corpus it was measured against no longer exists in this
  form: T-Pot prunes captures by retention age and Dionaea de-duplicates
  binaries by hash, so a 65-sample set legitimately becomes a different
  55-sample set over time. Old captures age out, new ones arrive. The 48/55
  figure describes the *surviving subset*, not a defect in the original
  measurement, and the two numbers are not directly comparable. The byte-size
  claim could not be checked at all, since file sizes were unreadable.
- **The rule's secondary clause does no work.** It requires two of five
  supporting strings, but two of those five — `OpenSCManagerA` and
  `WININET.dll` — are present in all 55 files, so the clause is always
  satisfied by those alone. In practice the rule reduces to *"is a Windows
  executable and contains `WNcry@2ol7`"*.
- Both of those universal strings are also common in entirely legitimate
  Windows software, and the rule's own metadata concedes that no benign
  executable corpus was tested. The false-positive rate is unmeasured, which is
  not the same as low.

The replacement rules in [`detection-rules.yara`](detection-rules.yara) anchor
on `launcher.dll` together with `PlayGame` — present in 55 of 55, and a
documented artefact of this specific dropper — and demote `WNcry@2ol7` to a
separate rule that reports whether the payload archive is intact. That change
is motivated by the two structural criticisms above, which hold regardless of
which corpus the rule is measured against. **The original rule file has not
been modified.**

The same retention-and-rotation mechanic is the honest explanation for the
coverage gap described earlier: the sensor is designed to age data out, so a
snapshot taken later necessarily sees less than a dashboard figure accumulated
across the full window. That is expected behaviour, not missing data.

---

## Finding 3 — The SMB traffic looks like a worm, with one exception

WannaCry propagates without an operator. That should produce a distinctive
traffic shape: very many source addresses, each contributing very little,
because each is simply an infected machine scanning at random. The data matches
that.

199 distinct source addresses appear across the log (198 external, plus the
Docker gateway). The distribution is a long tail — roughly 166 addresses
average under three events each. The busiest 17 account for 41.4% of events,
and the busiest 26 for 48.7%. There is no dominant attacker.

**The exception is a trio.** Three addresses in three unrelated ranges made
*exactly* 33 SMB connections each:

```
34.22.162.8     33
34.76.228.66    33
35.195.101.2    33
```

Identical totals across hosts that are supposed to be independent do not occur
by chance. This is the same signature the SSH report found in
[Finding 3](../cowrie/README.md#finding-3--work-queues-split-into-exactly-equal-shares),
where fleets divided a target list into equal shares — appearing here on a
different service and a different protocol.

**What this trio is has not been established.** The addresses fall in ranges
commonly associated with a large cloud provider, but **no registry lookup or
passive enrichment was performed for this report**, so that is an impression
rather than a finding. Confirming it needs the same passive enrichment the SSH
report used. Recorded here so the next analyst can pick it up.

Two further SMB sources stand out on volume alone: `115.79.202.30` with 13
events and `118.69.180.64` with 12. Neither shows the equal-share signature.

---

## Finding 4 — The non-SMB services collected defaults and scanners

**PPTP (114 events).** A single address, `213.209.159.136`, produced 102 of the
114 — connecting steadily every seven to eight minutes for the entire thirteen
hours. Regular, unattended, and by volume the single busiest source in the log.

**MongoDB (77 events).** Almost entirely two addresses: `192.155.89.166` (34)
and `138.197.219.187` (34). Both arrive in tight bursts — one delivered its
entire share inside two minutes. Consistent with database discovery scanning.

**MySQL (33 events).** Eight connections carried credentials, and every one was
the username `root` with an **empty password**. No password guessing, no
wordlist — just the default-configuration check.

**FTP (14 events).** Two logins, both `anonymous`, with the passwords
`IEUser@` and `anonymous@`. Both are stock scanner and browser strings rather
than anything an operator chose. Four further connections only probed for TLS
support via `AUTH TLS`.

**One FTP command deserves separate mention.** A connection issued
`MGLNDD_<sensor-address>_21`, a well-known scanner banner-grab whose argument
echoes the target's own public address back at it. **That address is the
honeypot's, and it has been redacted here and excluded from every file in this
repository**, per the repository scope. Worth knowing that this probe class
leaks it, if any raw Dionaea data is ever published from this sensor.

---

## Finding 5 — The sensor recorded connections and captures separately, and only one half survived

The readable `dionaea.json` was checked explicitly for every field that could
link a captured file to a connection:

| Field searched | Occurrences in 990 events |
|---|---:|
| `download` | 0 |
| `url` | 0 |
| `md5` | 0 |
| `sha` / `sha256` | 0 |
| `offer` | 0 |

All 990 records are connection accepts. Beyond the standard connection fields,
only 17 lines carry anything extra — the FTP command and credential objects
described above — and none of them references a file.

**The consequence is the single biggest gap in this analysis.** 55 samples sit
on disk with no recoverable link to the addresses that delivered them. The
mapping exists in `dionaea.sqlite`, which could not be opened. So this report
can say *what* was captured with confidence, and *what connected* with
confidence, but cannot join the two.

Everything that follows from that join is therefore unavailable: which source
addresses actually delivered malware as opposed to merely connecting, whether
the 55 came from 55 hosts or from five, and whether the equal-share trio in
Finding 3 delivered anything at all. **Reading `dionaea.sqlite` is the single
highest-value next step for this sensor**, and would close Findings 3 and 5
together.

---

## The wider malware corpus, and which sensor caught what

The 55 Dionaea samples were triaged alongside everything the honeypot captured
in the same period. The other families are recorded here because the detection
rules cover them, but **they arrived through Cowrie on SSH and Telnet, not
through Dionaea** — see
[`../cowrie/` Finding 6](../cowrie/README.md#finding-6--a-second-payload-family-and-one-that-cannot-be-named)
for the delivery detail on the two 17 August payloads, and the rest of that
report for RedTail across the full window.

**Counts in this table are scoped to the readable thirteen-hour window** and
are smaller than the equivalents in the SSH report, which covers all five days.
They are subsets, not disagreements.

| Family | Artefacts | Sensor | Vector | Confidence |
|---|---:|---|---|---|
| WannaCry | 55 | **Dionaea** | SMB / 445 | High |
| RedTail cryptominer | 7 | Cowrie | SSH / 22, SFTP-SCP push | Confirmed — installer self-identifies |
| XorDDoS | 1 | Cowrie | SSH / 22, SFTP upload | High |
| Mirai-style telnet probes | 9 (all 0 bytes) | Cowrie | Telnet / 23 | Behavioural only |
| Multi-arch dropper script | 1 | Cowrie | unknown | Family undetermined |

**RedTail** arrived as seven files pushed over SFTP/SCP in a single burst: two
shell scripts and five architecture builds (arm7, arm8, i686, riscv, x86_64).
That is **one delivery session** — `c71e5cdb87f1`, from `130.12.180.51` at
05:51:53Z — and it is the only one inside the readable window. The SSH report
records further RedTail deliveries across the full five days, including a
second source, `77.90.185.20`, which pushed byte-identical files. That host
does not appear anywhere in the 17 August log, so its activity fell in the
13–16 August window and could not be re-verified here.

**The family attribution is confirmed from the code itself, not inferred from
filenames.** The installer's random-name generator tries `openssl`, then
`/dev/urandom`, then `$RANDOM`, and if all three fail it falls back to a
hardcoded literal:

```sh
  # If all else fails
  echo "redtail"
```

That is the campaign naming itself in its own logic, and it is what the
detection rule anchors on rather than the `redtail.*` delivery filenames, which
an operator could rename at will.

**One distinction is worth keeping precise.** The confirmation lives in the
plaintext installer. The five ELF payloads remain UPX-packed, stripped and
statically linked, and contain **no plaintext indicators at all** — no pool
address, no wallet, no C2, and no self-identifying string. So the *campaign* is
confirmed; the *binaries* are still, on their own static evidence, only
"packed stripped ELF executables". Their mining pool and wallet remain
unrecovered and need unpacking in an isolated environment.

Prior analysis of the same sensor — covering log windows that were **not
readable here** — records an earlier related intrusion staging from
`217.60.195.113`, which the repository's own
[`../cowrie/indicators/infrastructure.csv`](../cowrie/indicators/infrastructure.csv)
already carries, and which historical Shodan data reportedly associates with
RedTail payload delivery. None of that is reproduced from data readable in this
pass; it is recorded as corroboration from the earlier work, not as an
independent observation.

**XorDDoS** is the opposite case — unpacked and self-evidencing. It carries the
family's hardcoded XOR key `BB2FA36AAA9541F0` six times, installs persistence
via `/etc/cron.hourly/gcc.sh` on a three-minute crontab entry, and spoofs a
2005-era Internet Explorer User-Agent with `Accept-Language: zh-cn`.

**The nine Mirai-style artefacts are all zero bytes.** Cowrie captured a shell
*redirection*, not a download — the bots ran a writable-directory probe across
`/var/run`, `/dev/shm`, `/tmp` and others, then aborted before fetching a
payload. There is no file to detect, so the corresponding rule targets log and
packet-capture text rather than binaries.

Nine is the count inside the readable thirteen-hour window. Prior analysis of
the full five-day window counted **42 sessions** running this credential
ladder, also with zero successful drops. The two figures are consistent — nine
is a subset of forty-two, not a contradiction — but only the nine were verified
here.

**The multi-arch dropper** fetches twelve six-character payloads from a single
host and runs each with the argument `bc`. None of the twelve was captured, the
script does not self-identify, and its delivery session predates the readable
log window. Lineage is consistent with Mirai or Gafgyt loaders; it is recorded
as undetermined rather than guessed.

**It was specifically checked against Panchan and does not match.** Panchan is
a Go-based SSH worm that peers over TCP/1919 with no central C2 and carries the
banner `pan-chan's mining island hi!`. Searching the entire Cowrie archive for
`pan-chan`, `panchan` and `mining island` returns **zero matches**, as does a
search of this dropper for `1919`. Its behaviour is also wrong for Panchan — it
pulls architecture builds from a hardcoded HTTP host rather than peering. If
Panchan reached this sensor, it did so outside the readable window.

---

## Detection rules

[`detection-rules.yara`](detection-rules.yara) holds ten YARA rules covering
every family above. They follow the style of the repository's existing
`yara/wannacry.yara`.

Three things about them should be stated plainly:

- **They have never been compiled or executed.** No `yara` binary was available
  on the analysis machine. Syntax is hand-reviewed only. Run `yarac` before
  deploying any of them.
- **Every coverage figure in their metadata is a projection**, derived from
  per-file string searches across this corpus, not from a rule run. Every
  string used was individually verified present in the sample it is attributed
  to.
- **No benign corpus was tested.** False-positive rates are unknown rather than
  low. Two rules are explicitly labelled hunting-only for this reason and
  should not be used for blocking.

One rule-writing detail worth recording, because it nearly produced a broken
signature: the XorDDoS command vocabulary (`denyip=`, `rmfile=`, `md5=`) is
plainly visible when the binary is decoded, but those strings are **assembled
at runtime and are not contiguous on disk**. A literal search for `denyip=`
returns zero matches. They are excluded from the rules. Strings that look
usable in a decoded view are not always usable in a signature.

**Sigma rules were deliberately not written.** They remain outstanding work.

---

## Indicators

Machine-readable versions live in [`indicators/`](indicators/).

### Captured malware

All 55 Dionaea samples are WannaCry. Full MD5 list with cluster assignment in
[`indicators/wannacry-md5.csv`](indicators/wannacry-md5.csv). **Binaries are not
included in this repository. Hashes only.** Hashes are the filenames the sensor
assigned; none was independently recomputed.

### Network indicators

| Indicator | Type | Context |
|---|---|---|
| `http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` | domain | WannaCry kill-switch; in 22 of 55 samples |
| `213.209.159.136` | ipv4 | 102 PPTP connections, sustained 13 h |
| `34.22.162.8`, `34.76.228.66`, `35.195.101.2` | ipv4 | SMB, exactly 33 events each |
| `192.155.89.166`, `138.197.219.187` | ipv4 | MongoDB discovery scanning, 34 each |
| `58.248.91.124` | ipv4 | 44 MSSQL connections |

### Host indicators

| Indicator | Family |
|---|---|
| `mssecsvc.exe`, `tasksche.exe`, `C:\%s\%s` | WannaCry drop artefacts |
| `launcher.dll` exporting `PlayGame` | WannaCry outer loader |
| `/etc/cron.hourly/gcc.sh` | XorDDoS persistence |
| `*/3 * * * * root /etc/cron.hourly/gcc.sh` | XorDDoS crontab entry |
| `~/.ssh/authorized_keys` locked with `chattr +ai` | RedTail persistence |

### Credentials observed

FTP: `anonymous` / `IEUser@`, `anonymous` / `anonymous@`.
MySQL: `root` with empty password, 8 occurrences.

All are defaults rather than guessed values. No credential list should be drawn
from this data.

---

## What could not be determined

1. **Sample-to-source attribution.** No linking field in the readable log;
   `dionaea.sqlite` unreadable. Highest-value next step.
2. **Four of the five days.** All rotated logs are gzip-compressed.
3. **Whether the 55 samples all fall inside the observation window.** File
   timestamps could not be read.
4. **Filename-versus-content verification.** No hashing tool available.
5. **Exact file sizes**, which leaves the truncation-versus-variant question in
   Finding 2 open.
6. **Any behavioural claim about the samples.** No disassembler was available.
   Everything here comes from printable strings and logged commands, never from
   code analysis.
7. **RedTail mining pool and wallet**, which sit inside the UPX-compressed
   stream.
8. **ASN, country and operator enrichment** for the addresses in this report.
   The SSH report carries that enrichment; this one does not.
9. **YARA rule validation.** No `yara` binary available.

---

## Scope

One sensor, passive collection only. Nothing was scanned, probed or contacted;
no sample was executed, unpacked or modified. No malware binaries and no
captured private keys are committed to this repository.

**Sensor identity is excluded deliberately and completely.** That means not
only the public IP address but the hostname, the administrative username, the
non-standard SSH port and the hosting provider. Publishing any of them would
let a reader connect this analysis to the account that pays for the machine,
and from there to a real identity and home network. The exclusion has been
checked across every file in this repository, including the FTP scanner banner
described in Finding 4, which echoes the sensor's own address back at it in
the raw log. **Anyone publishing further extracts from this sensor should
re-run that check first** — the raw data contains these values even though the
analysis does not.

This report covers approximately thirteen hours of 17 August 2026, not the full
13–17 August window. See [Read this before the
numbers](#read-this-before-the-numbers).
