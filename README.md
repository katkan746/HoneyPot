# T-Pot Honeypot Analysis

Analysis of attack data from a single T-Pot honeypot sensor, 13–17 August 2026.
A honeypot is a machine that is exposed to the internet on purpose, so that
attacks against it can be recorded safely.

The sensor recorded roughly 762,000 events over the five days, spread across ten
honeypot services. About 192,000 of those came from a commercial internet
scanning company rather than an attacker, leaving roughly 569,000 that can
reasonably be called attacks. This repository covers the SSH and Telnet sensor.

![Bar chart of attacks recorded by each honeypot sensor between 13 and 17 August 2026. Honeytrap 303k, Cowrie 243k, RDPHoneypot 153k, Sentrypeer 36k, Dionaea 14k, Honeyaml 5k, Tanner 2k, ConPot 2k, Heralding 1k and H0neytr4p 1k, from a total of 762k.](/images/honeypot-attacks-by-sensor.svg)

## Contents

| Folder | Sensor | Events | Sessions |
|---|---|---|---|
| [`cowrie/`](cowrie/) | SSH and Telnet | 243k | 50,345 |

**[`cowrie/`](cowrie/)** holds the report. It covers 50,345 SSH and Telnet
sessions and separates the traffic by what the attackers actually did once they
were connected. Three groups behaved in completely different ways: one tested
whether the machine was a honeypot and withdrew without installing anything, one
ran no checks at all and deployed malware immediately, and one only
authenticated and typed nothing — validating stolen credentials for later use.

Source addresses, file hashes and payload retrieval URLs are listed inline in
the report.

## Scope

One sensor, five days, passive collection only. Nothing was scanned, probed or
contacted. All enrichment used passive sources and historical Shodan data.

No malware binaries and no captured private keys are committed to this
repository.
