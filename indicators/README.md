# Indicators

| File | Contents |
|---|---|
| `hosts.csv` | Source addresses, with prefix, ASN, country, behavioural role and client fingerprint |
| `hassh.csv` | HASSH client fingerprints, volumes and the role each maps to |
| `payload-sha256.csv` | RedTail payload hashes and sizes |
| `infrastructure.csv` | Payload retrieval endpoints and the persistence key comment |
| `ssh-public-keys.csv` | Public keys offered during authentication |

**Not every address here is an attacker.** The ten `85.217.149.0/24` rows are
Modat B.V., a commercial scanning company, and account for roughly a quarter of
the corpus. They are included because they dominate the raw volume and because
excluding them silently is how that volume gets mistaken for attack traffic.
Their role column reads `commercial-scanner`.

**Two addresses are Tor exit nodes** (`192.42.116.18`, `185.220.101.105`).
Blocking them blocks Tor, not an actor. The key they offered is the durable
identifier; the exit address is not.

