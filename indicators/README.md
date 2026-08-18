# Indicators

Machine-readable form of the indicators in the root `README.md`. Nothing here
is new evidence — every row is transcribed from that analysis, and the analysis
is the authority. If the two ever disagree, the analysis wins.

| File | Contents |
|---|---|
| `hosts.csv` | Source addresses, with prefix, ASN, country, behavioural role and client fingerprint |
| `hassh.csv` | HASSH client fingerprints, volumes and the role each maps to |
| `payload-sha256.csv` | RedTail payload hashes and sizes |
| `infrastructure.csv` | Payload retrieval endpoints and the persistence key comment |
| `ssh-public-keys.csv` | Public keys offered during authentication |

## Reading these before you block on them

**Not every address here is an attacker.** The ten `85.217.149.0/24` rows are
Modat B.V., a commercial scanning company, and account for roughly a quarter of
the corpus. They are included because they dominate the raw volume and because
excluding them silently is how that volume gets mistaken for attack traffic.
Their role column reads `commercial-scanner`. Decide deliberately whether your
environment wants them blocked.

**Two addresses are Tor exit nodes** (`192.42.116.18`, `185.220.101.105`).
Blocking them blocks Tor, not an actor. The key they offered is the durable
identifier; the exit address is not.

**Prefer the fingerprint to the address.** The recon fleet in `hosts.csv`
spans four /24s and two ASNs, and the largest ASN block still leaves a third
of it operating. `hassh.csv` is the column that survives relocation.

## Conventions

- Empty cells mean the source analysis does not state a value — not zero.
- `first_seen` / `last_seen` are only populated where the analysis gives a
  date. Most rows are blank; the observation window as a whole is 13–17 August
  2026.
- `sessions` counts distinct sessions; `events` counts sensor documents. They
  are not interchangeable.
- Percentages in `hassh.csv` are shares of the 50,345 SSH sessions. The two
  smallest are computed here (0.9%, 0.3%) and left blank in the analysis.
- `bf7dbf67` is recorded in its truncated published form; the other
  fingerprints are full 32-character MD5.
- Addresses are not defanged, so these files can be fed to tooling directly.
- `172.30.0.1` is deliberately absent: it is the Docker gateway, an artifact of
  the sensor's own network, not a source. Filter RFC1918 before publishing any
  source table derived from raw aggregations.
- No binaries, no captured private keys, and no sensor address appear in this
  directory or anywhere else in the repository.
