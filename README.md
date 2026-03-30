# Normal and beaconing log generator

A small utility that writes **synthetic network-style events** to CSV. The data is shaped like UDM (Unified Data Model) fields you might see from a proxy or Zscaler-style pipeline: timestamps, NAT IPs, target hostnames, protocols, HTTP metadata, bytes, and `ALLOW` actions.

Roughly **80%** of benign rows are irregular “noise” to common SaaS and update domains; **20%** are telemetry-style hosts. **Additional rows** simulate **C2 beaconing** to a configurable (or default synthetic) hostname on a delay/jitter schedule. Beacons use **one fixed synthetic client** and a **small rotating C2 edge IP pool** (stable hostname, CDN-like IPs) so detection grouping sees dense series. Benign traffic uses **2–5 hosts per UTC day** from a small pool. See [BEACONING.md](BEACONING.md); each run writes `*_beaconing_explanation.txt` with parameters and pools used.

## Requirements

- **Python 3.6+** (stdlib only; see `requirements.txt`)

## Usage

From the project directory:

```bash
python normal_and_beaconing_log_generator.py
```

Defaults: **last 5 days (UTC, rolling from current time)**, default C2 hostname with a **32-character** random label under `.c2.sim`, beacon **delay 300 s**, **jitter ±60 s**, protocol **HTTPS**. Outputs **`synthetic_zscaler_noise_with_periodic.csv`** and **`synthetic_zscaler_noise_with_periodic_beaconing_explanation.txt`**.

### CLI parameters

| Option | Description |
|--------|-------------|
| `--start-date YYYY-MM-DD` | UTC window start (inclusive). Use with `--end-date`, or omit both for last 5 days. |
| `--end-date YYYY-MM-DD` | UTC window end (inclusive, end of that calendar day). |
| `--c2-domain HOST` | Simulated C2 hostname for beacon rows. |
| `--beacon-delay SEC` | Base seconds between beacons. |
| `--beacon-jitter SEC` | ± jitter (seconds) on each interval. |
| `--beacon-protocol PROTO` | e.g. `HTTPS`, `HTTP`. |
| `-o`, `--output PATH` | CSV output path. |
| `--event-target N` | Target count of benign noise/telemetry rows (beacons are added on top). |
| `--beacon-doc PATH` | Where to write the per-run beacon explanation (default: `<csv_stem>_beaconing_explanation.txt`). |
| `--seed N` | Optional RNG seed for reproducible runs. |

Example with an explicit window and custom C2:

```bash
python normal_and_beaconing_log_generator.py --start-date 2025-03-01 --end-date 2025-03-07 --c2-domain bad.example.net --beacon-delay 120 --beacon-jitter 30 --beacon-protocol HTTPS -o out.csv
```

## Configuration

You can still edit pools and defaults at the top of `normal_and_beaconing_log_generator.py` (internal users, NAT pool, benign domains, default beacon settings). CLI flags override behavior at runtime.

Events are sorted by timestamp before writing.

## Output columns

The CSV includes fields such as `timestamp`, `udm.target.asset.hostname`, `udm.principal.nat_ip`, `udm.network.application_protocol`, HTTP-related keys, ASN/geo-style placeholders, and `internal_user`.

## Disclaimer

This data is **fabricated for testing and demos**. It does not represent real users, traffic, or vendors.
