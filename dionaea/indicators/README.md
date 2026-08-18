# Indicators

Machine-readable form of the indicators in [`../README.md`](../README.md).
Nothing here is new evidence — every row is transcribed from that analysis, and
the analysis is the authority. If the two ever disagree, the analysis wins.

| File | Contents |
|---|---|
| `services.csv` | Dionaea services, ports and event counts |
| `hosts.csv` | Source addresses, with service, volume and behavioural role |
| `wannacry-md5.csv` | All 55 captured samples, with cluster and per-marker presence |
| `infrastructure.csv` | Network and host indicators across every family triaged |
| `detection-coverage.csv` | YARA rules, projected coverage and deployment guidance |

## Reading these before you block on them

**These figures cover roughly thirteen hours of 17 August, not the full 13–17
August window.** The rotated logs and the sensor database could not be read.
990 connection events were analysed against a dashboard figure of 14,000 for
the window — about 7.1%. Nothing here should be read as characterising the
full period. See the analysis for the full coverage table.

**No source address here is linked to a captured sample.** The readable
Dionaea log contains no `download`, `url`, `md5` or `sha` field — it records
connections only. `hosts.csv` says who connected and `wannacry-md5.csv` says
what was captured, and there is no data available to join them. Do not read
adjacency in this directory as attribution.

**The hashes are filenames, not computed values.** Dionaea names captured
files by their MD5. No hashing tool was available on the analysis machine, so
no filename-versus-content check was performed. Treat them as sensor-asserted.

**Roles in `hosts.csv` are behavioural labels, not attribution.** They describe
what an address did in this log. No registry lookup, ASN mapping or passive
enrichment was performed for this report — unlike
[`../../cowrie/indicators/`](../../cowrie/indicators/), which carries that
enrichment. The `asn` and `country` columns are present for schema
compatibility and are empty throughout.

**`detection-coverage.csv` records projections, not test results.** No `yara`
binary was available, so no rule in this repository has been compiled or
executed. The `deploy_for_blocking` column is the one to read first: two rules
are marked `no` because they are hunting heuristics that will fire on benign
files.

## Conventions

- Empty cells mean the source analysis does not state a value — not zero.
- `first_seen` / `last_seen` are `2026-08-17` throughout, because that is the
  only date present in the readable log. This reflects coverage, not the true
  lifespan of any indicator.
- `events` counts sensor documents from `dionaea.json`. The `bistreams` column
  in `services.csv` counts stream files on disk for the same day; the two use
  different denominators and are not interchangeable.
- Shares in `services.csv` are shares of the 990 readable events.
- `hosts.csv` lists the 26 busiest sources. 199 distinct source addresses
  appear in the log; the long tail of roughly 166 addresses averaging under
  three events each is not enumerated.
- Addresses are not defanged, so these files can be fed to tooling directly.
- `172.23.0.1` is deliberately absent: it is the Docker bridge gateway, an
  artifact of the sensor's own network, not a source. It appears exactly once
  in the raw log. Filter RFC1918 before publishing any source table derived
  from raw aggregations.
- No sensor identity appears here: not the public address, hostname,
  administrative username, SSH port or hosting provider. The public address is
  echoed back by the `MGLNDD_<address>_21` FTP scanner banner recorded in the
  raw log — check for that string, and for the other four values, before
  publishing any raw Dionaea extract from this sensor.
- No binaries, no captured private keys, and no sensor address appear in this
  directory or anywhere else in the repository.
