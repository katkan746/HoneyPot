SMB Honeypot Analysis — What Arrives When You Leave Windows File Sharing Open
This report covers the Dionaea sensor from the same T-Pot honeypot described in
the repository README. Where cowrie/ asks how
many separate attackers are behind the SSH and Telnet traffic, this report asks
a different question: what actually gets deposited on an exposed Windows file
share?

The answer is: one thing, over and over. Dionaea captured 55 malware samples,
and every one of them is the same WannaCry dropper chain — a worm that has been
propagating unattended since 2017.

That makes the actor question the wrong one to ask of this data. WannaCry's
worm component spreads on its own, and it lost central direction when the
kill-switch domain was sinkholed in May 2017. What reaches the sensor now
arrives from machines that were infected years ago, never cleaned up, and are
still scanning at random. The addresses behind this traffic are casualties of
the outbreak rather than operators running a campaign.

Executive summary
This section is written for readers who do not work in security. The rest of
the report assumes technical knowledge.

What was done. One machine was connected to the internet and left to be
attacked. It pretended to offer ordinary business services — Windows file
sharing, databases, file transfer — and recorded what was sent to it. This
report covers Windows file sharing, which received two thirds of the traffic
and delivered every malware sample collected.

What arrived. Two thirds of the connections went to a single service:
Windows file sharing, the mechanism that lets office computers share folders
with each other. It is not supposed to be reachable from the internet at all.
Every one of the 55 malware samples collected came in through it.

The main finding. All 55 samples are the same thing: WannaCry, the
ransomware worm that spread worldwide in May 2017. Nine years on it is still
circulating, not because anyone is running a campaign, but because infected
machines that were never cleaned up keep scanning the internet and infecting
each other. What the honeypot recorded is not an attack aimed at it. It is
background noise from an epidemic that was never fully cleared.

Why that matters. WannaCry spreads through a flaw that Microsoft patched in
March 2017. Any machine still catching it has been unpatched for nine years.
The practical lesson is unglamorous and worth repeating: file sharing should
never be exposed to the internet, and a patch released in 2017 should have been
applied in 2017.

One further point is worth drawing out:

There is no attacker here to identify. The machines sending these samples
are themselves victims — infected long ago, still running, still scanning.
That changes the response: an address seen in this data is a host whose owner
needs telling, not an adversary to be blocked. Blocking it removes one
infected machine from view and leaves the rest of the population untouched.

Attack volume by sensor

Attacks recorded by each sensor over the five-day window, taken from the T-Pot
dashboard totals. Dionaea, fifth of the ten, is the source for this report.

Observation window
2026-08-17T01:55:20Z to 2026-08-17T15:06:09Z — thirteen hours and eleven
minutes, taken as the earliest and latest timestamps in the analysed log. 990
connection events, 55 captured samples.
Where a proportion is given below, it is a proportion of the 990.

Finding 1 — Two thirds of the traffic is Windows file sharing
Of 990 connection events, 675 went to SMB on port 445.

| Service | Port | Events | Shares |
| :--- | :--- | :--- | :--- |
| smbd | 445 | 675 | 68.2% |
| pptpd | 1723 | 114 | 11.5% |
| mongod | 27017 | 77 | 7.8% |
| mssqld | 1433 | 51 | 5.2% |
| mysqld | 3306 | 33 | 3.3% |
| httpd | 81 | 17 | 1.7% |
| ftpd | 21 | 14 | 1.4% |
| epmapper | 135 | 5 | 0.5% |
| mqttd | 1883 | 3 | 0.3% |
| ftpdatalisten | ephemeral | 1 | 0.1% |
| **Total** | | **990** | |

Everything below this table concerns SMB only. The non-SMB services are
retained here for proportion and are not analysed further; they collected
default-credential checks and discovery scanning, and delivered nothing. The
credentials they collected are listed under Indicators.

Finding 2 — All 55 captured samples are the same 2017 worm
Every file in the binaries/ directory begins with MZ, the Windows
executable signature. There are no Linux binaries, no scripts, and no archives.
All 55 are the WannaCry dropper chain.

Structure. An outer executable exports a function called PlayGame from a
component named launcher.dll, and imports the Windows resource and process
APIs. It carries the drop filename mssecsvc.exe and the path format string `C:\%s\%s`. Inside it sits a second executable whose oversized resource section
holds a password-protected ZIP archive containing the ransomware payload —
tasksche.exe, @WanaDecryptor@, taskdl.exe, taskse.exe.

Marker distribution, measured by searching each of the 55 files
individually:

| Marker | Present | Note |
| :--- | :--- | :--- |
| launcher.dll | 55 / 55 | outer loader export |
| PlayGame | 55 / 55 | outer loader export |
| OpenSCManagerA | 55 / 55 | generic Windows API |
| WININET.dll | 55 / 55 | generic Windows API |
| WNcry@2ol7 | 48 / 55 | ZIP password for the payload |
| CryptEncrypt | 48 / 55 | |
| CryptDestroyKey | 48 / 55 | |
| kill-switch domain | 22 / 55 | |

Two sub-clusters. 48 files carry the complete marker set. Seven do not, and
they are the same seven files in each case:

* **dd0f515ed8fd732bbbdf78db2f93c2c6** (SHA-256: `cf7e0fae9a07e20f74b257bbd4fc54e195a1ffb0cd8996e916e41a095c5ac0cd`)
* **9a936a0b3b66b6ad153f1a59426da531** (SHA-256: `3eafea823d5bd21187e5b30e894aaf273f6f0dd18af80b949c79f4874ab2c6fb`)
* **5630a1e4d520ff06dd5e20a95101ab05** (SHA-256: `bb081d176180ae4c30bb062d8bb1858330861d78c670bc3e4c2933a4459cd0ad`)
* **a21f7847f4edfb503107c343fcdf5ab6** (SHA-256: `6018e1bf68cdedee60faa9ed7020ddd03a10269ae0ac32f24395cbfc21ec826e`)
* **66bb0b650bfdf95d6000f97d4bbf0f25** (SHA-256: `0ce349c3dba0d77585320010f0531548729455aaedd56c2ecb9d5fb7bd4d2abc`)
* **1d7be28d97a57aeaeca8e9b96057a526** (SHA-256: `c2e3ce39da608fa9257f8d1779df350cc3c9f73e60a6261dbf89d9b1938900cc`)
* **37c07aa4965f5f1bd40600ea762a040f** (SHA-256: `b2db241fa6eb5c63c67d9768b20d401b19fb526ff3e65a0ca7992183ff70e095`)

Indicators
Machine-readable versions live in indicators/.

Captured malware
All 55 Dionaea samples are WannaCry. Full MD5 and SHA-256 list in indicators/wannacry-hashes.csv. Binaries are not
included in this repository. Hashes only.

Host indicators

| Indicator | Context |
| :--- | :--- |
| mssecsvc.exe, tasksche.exe, `C:\%s\%s` | WannaCry drop artefacts |
| launcher.dll exporting PlayGame | WannaCry outer loader, 55 / 55 |
| WNcry@2ol7 | payload archive password, 48 / 55 |
| http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com | kill-switch domain, 22 / 55 |

Indicators for the families captured by the SSH and Telnet sensor are in ../cowrie/indicators/.

Scope
One sensor, passive collection only. Nothing was scanned, probed or contacted;
no sample was executed, unpacked or modified. No malware binaries and no
captured private keys are committed to this repository.
