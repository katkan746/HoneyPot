# T-Pot Honeypot Analysis

Analysis of attack data from a single T-Pot honeypot sensor, 13–17 August 2026.
A honeypot is a machine that is exposed to the internet on purpose, so that
attacks against it can be recorded safely.

The sensor recorded roughly 762,000 attacks over the five days, spread across
ten honeypot services. This repository covers the SSH and Telnet sensor.

![Bar chart of attacks recorded by each honeypot sensor between 13 and 17 August 2026. Honeytrap 303k, Cowrie 243k, RDPHoneypot 153k, Sentrypeer 36k, Dionaea 14k, Honeyaml 5k, Tanner 2k, ConPot 2k, Heralding 1k and H0neytr4p 1k, from a total of 762k.](docs/images/honeypot-attacks-by-sensor.svg)

## Contents

| Folder | Sensor | Events |
|---|---|---|
| [`cowrie/`](Cowrie/) | SSH and Telnet | 243k |

**[`cowrie/`](Cowrie/)** holds the report. It asks how many separate attackers
are really behind the traffic, and finds that 50,345 sessions from thousands of
addresses resolve to about six attack tools. It also contains the indicators —
addresses, fingerprints, file hashes and keys — as CSV, in
[`/indicators/`](/indicators/).

## Scope

One sensor, five days, passive collection only. Nothing was scanned, probed or
contacted. All enrichment used passive sources and historical Shodan data.
No malware binaries and no captured private keys are committed to this
repository.
