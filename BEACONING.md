# Simulated beaconing

This project can add **synthetic command-and-control (C2) beaconing** rows to the CSV alongside benign traffic. The goal is to produce **labeled-style test data** for analytics, detection engineering, or training—**not** to model a specific real malware family.

## What “beaconing” means here

In this generator, a **beacon** is a row whose destination hostname is your configured **C2 domain** (or the default synthetic hostname). Beacons are placed on a **simple timer**:

1. Start at the **beginning of the configured UTC time window** (or the first valid time in range).
2. After each beacon, the next time is **previous time + (base delay + U)**, where **U** is a random integer uniformly drawn from **[-jitter, jitter]** (in seconds).
3. The step is clamped so the interval is **at least 1 second**.
4. Timestamps stop once they would exceed the **end of the window**.

There is **no payload encoding**, **no real protocol handshake**, and **no network I/O**—only CSV fields that resemble proxy or Zscaler-style UDM exports.

## Stable SNI vs rotating target IP (CDN-style)

Real logs often show a **stable hostname** (SNI / HTTP Host) while **`udm.target.ip` changes** across a small edge pool (CDN, load balancer, anycast). The generator models that with a **fixed small set of C2 edge IPs** per run. For each **UTC calendar day**, roughly **90%** of beacon rows reuse one **primary** edge IP for that day; the rest use another IP from the same pool so grouping by `(hostname, ip)` still yields **few, high-volume series** instead of one row per random IP.

## One beacon host; few benign hosts per day

All **beacon** rows come from **one synthetic compromised machine** (same `internal_user` and `udm.principal.nat_ip` for the whole run) so client-side grouping and inter-arrival analysis behave like a single implant.

**Benign** rows draw from a **small pool** of machines; for each **UTC day**, only **2–5** of those hosts are “active” (random subset, stable for that day). That keeps daily cardinality low while allowing different subsets across the week.

## Parameters (CLI)

| Parameter | Meaning |
|-----------|---------|
| `--start-date` / `--end-date` | Inclusive UTC calendar-day bounds (`YYYY-MM-DD`). Omit **both** to use the **last 5 days** from “now” (rolling window, UTC). |
| `--c2-domain` | Hostname used for every beacon row. If omitted, a **32-character random label** plus the suffix `.c2.sim` (valid single-label length). |
| `--beacon-delay` | Base seconds between beacons. |
| `--beacon-jitter` | Seconds of random jitter **added** to the delay each step (±). |
| `--beacon-protocol` | Value written to `udm.network.application_protocol` for beacon rows (e.g. `HTTPS`, `HTTP`). |

Benign rows are controlled separately with `--event-target` (target count of noise/telemetry rows); **all** beacons that fit in the window are always emitted in addition.

## Per-run explanation file

Each successful run writes a **companion text file** next to the CSV (unless you override `--beacon-doc`). It records the exact window, C2 hostname, delay, jitter, protocol, and counts. Use it as the ground truth for what was simulated in that dataset.

## Ethics and scope

- Use only on systems and data you are allowed to test.
- Do not point tools at real hosts you do not own without authorization.
- Synthetic hostnames in this tool are **random** and should not resolve to real services; treat output as **fabricated**.
