import argparse
import csv
import random
import string
import datetime
from datetime import timedelta, timezone

# ---------------------------------------------------------
# CONFIGURATION (defaults; overridden by CLI)
# ---------------------------------------------------------

OUTPUT_FILE = "synthetic_zscaler_noise_with_periodic.csv"
DEFAULT_EVENT_TARGET = 6000
DEFAULT_RANGE_DAYS = 5

# Internal user source IP pool (simulate multiple users)
INTERNAL_USERS = [
    "10.10.1." + str(i) for i in range(10, 60)
]

# NAT pool (external egress IPs)
NAT_POOL = [
    "84.14.50." + str(i) for i in range(1, 30)
]

# Benign recurring destinations (Office365, Teams, Windows Update, browsers)
NOISE_DOMAINS = [
    ("ecs.office.com", "HTTPS"),
    ("login.microsoftonline.com", "HTTPS"),
    ("outlook.office.com", "HTTPS"),
    ("teams.microsoft.com", "HTTPS"),
    ("windowsupdate.com", "HTTP"),
    ("ctldl.windowsupdate.com", "HTTP"),
    ("api.github.com", "HTTPS"),
    ("api.dropbox.com", "HTTPS"),
    ("www.bing.com", "HTTPS"),
    ("www.google.com", "HTTPS")
]

# Slightly more periodic but still benign stream (e.g. telemetry)
PERIODIC_DOMAINS = [
    ("settings-win.data.microsoft.com", "HTTPS"),
    ("v10.events.data.microsoft.com", "HTTPS"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Microsoft-Delivery-Optimization/10.0",
    "Windows-Update-Agent/10.0.19041",
    "Teams/1.7.0",
    "Outlook/16.0",
]

ASN_DATA = [
    (8075, "microsoft corporation"),
    (16625, "akamai technologies inc."),
    (20940, "akamai international bv"),
]

DEFAULT_BEACON_DELAY_S = 300
DEFAULT_BEACON_JITTER_S = 60
DEFAULT_BEACON_PROTOCOL = "HTTPS"

# Few synthetic endpoints; benign activity only from a small subset per UTC day.
MACHINE_POOL_SIZE = 14
MIN_MACHINES_ACTIVE_PER_DAY = 2
MAX_MACHINES_ACTIVE_PER_DAY = 5

# C2 hostname resolves to a small CDN-style edge pool (stable SNI, few rotating IPs).
C2_EDGE_IP_COUNT = 4
# Within a UTC day, most beacons reuse the same edge IP so grouping sees a stable series.
C2_PRIMARY_EDGE_WEIGHT = 0.90

# Single ASN/org for all C2 edge IPs (one provider).
C2_ASN = 20940
C2_ORG = "akamai international bv"

# ---------------------------------------------------------
# TIME RANGE & C2 DEFAULTS
# ---------------------------------------------------------

def parse_date_start_utc(s):
    """YYYY-MM-DD -> start of that calendar day in UTC."""
    d = datetime.datetime.strptime(s.strip(), "%Y-%m-%d").date()
    return datetime.datetime(d.year, d.month, d.day, tzinfo=timezone.utc)


def parse_date_end_utc(s):
    """YYYY-MM-DD -> last microsecond of that calendar day in UTC."""
    start = parse_date_start_utc(s)
    return start + timedelta(days=1) - timedelta(microseconds=1)


def default_time_range_utc():
    """Last DEFAULT_RANGE_DAYS full days ending at current UTC instant."""
    end = datetime.datetime.now(timezone.utc)
    start = end - timedelta(days=DEFAULT_RANGE_DAYS)
    return start, end


def random_alphanumeric(n, rng=random):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(n))


def default_c2_domain(rng=random):
    """
    Synthetic C2 hostname: one 32-character random label (valid DNS label length) plus .c2.sim.
    """
    return f"{random_alphanumeric(32, rng=rng)}.c2.sim"


# ---------------------------------------------------------
# BEACON SCHEDULE
# ---------------------------------------------------------

def generate_beacon_times(range_start, range_end, delay_s, jitter_s, rng=random):
    """Monotonic beacon timestamps in [range_start, range_end]."""
    times = []
    t = range_start
    while t <= range_end:
        times.append(t)
        step = delay_s + rng.randint(-jitter_s, jitter_s)
        if step < 1:
            step = 1
        t = t + timedelta(seconds=step)
    return times


def random_public_ipv4(rng=random):
    return ".".join(str(rng.randint(1, 255)) for _ in range(4))


def build_machine_pool(size=MACHINE_POOL_SIZE, rng=random):
    """Fixed internal + NAT pairs (one row = one consistent client)."""
    n = min(size, len(INTERNAL_USERS), len(NAT_POOL))
    idxs = rng.sample(range(len(INTERNAL_USERS)), n)
    nat_idxs = rng.sample(range(len(NAT_POOL)), n)
    return [
        {"internal_user": INTERNAL_USERS[i], "nat_ip": NAT_POOL[j]}
        for i, j in zip(idxs, nat_idxs)
    ]


def utc_calendar_days_inclusive(range_start, range_end):
    d = range_start.date()
    end_d = range_end.date()
    days = []
    while d <= end_d:
        days.append(d)
        d += timedelta(days=1)
    return days


def active_machines_by_day(machines, range_start, range_end, seed):
    """Few hosts emit benign traffic on any given UTC day."""
    out = {}
    lo = min(MIN_MACHINES_ACTIVE_PER_DAY, len(machines))
    hi = min(MAX_MACHINES_ACTIVE_PER_DAY, len(machines))
    if hi < 1:
        return out
    lo = max(1, lo)
    hi = max(lo, hi)
    for d in utc_calendar_days_inclusive(range_start, range_end):
        if seed is not None:
            day_seed = (seed * 1_000_003 + d.toordinal() * 0xC0) & 0x7FFFFFFF
            r = random.Random(day_seed)
            k = r.randint(lo, hi)
            out[d] = r.sample(machines, k)
        else:
            k = random.randint(lo, hi)
            out[d] = random.sample(machines, k)
    return out


def pick_machine_for_benign_ts(ts, active_by_day, rng=random):
    day = ts.astimezone(timezone.utc).date()
    pool = active_by_day.get(day)
    if not pool:
        pool = list(active_by_day.values())[-1] if active_by_day else []
    if not pool:
        return None
    return rng.choice(pool)


def c2_edge_ip_for_beacon(ts, edge_ips, c2_domain, rng=random):
    """Mostly one edge IP per UTC day; occasional hop to another IP in the small pool."""
    if not edge_ips:
        return random_public_ipv4(rng)
    day_ord = ts.astimezone(timezone.utc).date().toordinal()
    primary_i = (day_ord + len(c2_domain)) % len(edge_ips)
    if rng.random() < C2_PRIMARY_EDGE_WEIGHT:
        return edge_ips[primary_i]
    alt = [i for i in range(len(edge_ips)) if i != primary_i]
    return edge_ips[rng.choice(alt)]


def make_entry(
    ts,
    domain,
    proto,
    *,
    target_ip=None,
    target_asset_ip=None,
    nat_ip=None,
    internal_user=None,
    asn=None,
    org=None,
):
    if asn is None or org is None:
        asn, org = random.choice(ASN_DATA)
    if target_ip is None:
        target_ip = random_public_ipv4()
    if target_asset_ip is None:
        target_asset_ip = target_ip

    row = {
        "timestamp": ts.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "udm.target.ip": target_ip,
        "udm.principal.nat_ip": nat_ip if nat_ip is not None else random.choice(NAT_POOL),
        "udm.target.asset.hostname": domain,
        "udm.target.asset.ip": target_asset_ip,
        "udm.target.ip_geo_artifact.network.asn": asn,
        "udm.target.ip_geo_artifact.network.carrier_name": org,
        "udm.target.ip_geo_artifact.network.organization_name": org,
        "udm.network.application_protocol": proto,
        "udm.network.http.method": random.choice(["GET", "POST", ""]),
        "udm.network.http.user_agent": random.choice(USER_AGENTS),
        "udm.network.http.response_code": random.choice([200, 204, 304, 404]),
        "udm.network.received_bytes": random.randint(200, 20000),
        "udm.network.sent_bytes": random.randint(200, 5000),
        "udm.security_result.action": "ALLOW",
        "internal_user": internal_user
        if internal_user is not None
        else random.choice(INTERNAL_USERS),
    }
    return row

# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------

def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Synthetic UDM-style proxy logs: benign noise, benign periodic traffic, and simulated C2 beaconing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--start-date",
        metavar="YYYY-MM-DD",
        help="UTC start of log window (inclusive). If omitted with --end-date, both must be omitted (uses last %d days)." % DEFAULT_RANGE_DAYS,
    )
    p.add_argument(
        "--end-date",
        metavar="YYYY-MM-DD",
        help="UTC end of log window (inclusive, end of that calendar day).",
    )
    p.add_argument(
        "--c2-domain",
        help="Hostname for simulated C2 beaconing. Default: random 32-char label under .c2.sim",
    )
    p.add_argument(
        "--beacon-delay",
        type=int,
        default=DEFAULT_BEACON_DELAY_S,
        metavar="SEC",
        help="Base interval in seconds between simulated beacon connections",
    )
    p.add_argument(
        "--beacon-jitter",
        type=int,
        default=DEFAULT_BEACON_JITTER_S,
        metavar="SEC",
        help="Uniform jitter in seconds (+/-) added to each beacon interval",
    )
    p.add_argument(
        "--beacon-protocol",
        default=DEFAULT_BEACON_PROTOCOL,
        help="Application protocol for beacon rows (e.g. HTTPS, HTTP)",
    )
    p.add_argument(
        "-o", "--output",
        default=OUTPUT_FILE,
        help="Output CSV path",
    )
    p.add_argument(
        "--event-target",
        type=int,
        default=DEFAULT_EVENT_TARGET,
        metavar="N",
        help="Target number of benign noise rows; beacon rows are added in full for the time window",
    )
    p.add_argument(
        "--beacon-doc",
        metavar="PATH",
        help="Write per-run beacon explanation to this path. Default: <output_stem>_beaconing_explanation.txt",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional RNG seed for reproducible output",
    )
    return p


def resolve_time_range(args):
    if args.start_date is None and args.end_date is None:
        return default_time_range_utc()
    if args.start_date is None or args.end_date is None:
        raise SystemExit("Provide both --start-date and --end-date, or neither (for last %d days)." % DEFAULT_RANGE_DAYS)
    start = parse_date_start_utc(args.start_date)
    end = parse_date_end_utc(args.end_date)
    if start > end:
        raise SystemExit("--start-date must be on or before --end-date.")
    return start, end


def default_beacon_doc_path(output_csv):
    if output_csv.lower().endswith(".csv"):
        return output_csv[:-4] + "_beaconing_explanation.txt"
    return output_csv + "_beaconing_explanation.txt"


def write_beacon_explanation(
    path,
    start,
    end,
    c2_domain,
    delay_s,
    jitter_s,
    protocol,
    beacon_count,
    noise_count,
    output_csv,
    c2_edge_ips,
    beacon_internal,
    beacon_nat,
):
    lines = [
        "Simulated beaconing — run summary",
        "=================================",
        "",
        "This file describes the synthetic C2 beaconing inserted into the companion CSV.",
        "It is for testing and training only; no real infrastructure is contacted.",
        "",
        f"Output CSV: {output_csv}",
        f"Time range (UTC): {start.isoformat()} .. {end.isoformat()}",
        f"C2 hostname (synthetic): {c2_domain}",
        f"C2 edge IP pool (CDN-style, small): {', '.join(c2_edge_ips)}",
        f"Beacon protocol: {protocol}",
        f"Base delay between beacons: {delay_s} seconds",
        f"Jitter per interval: +/- {jitter_s} seconds (uniform integer, clamped so step >= 1 s)",
        f"Beacon events written: {beacon_count}",
        f"Benign noise rows (target): {noise_count}",
        "",
        "Endpoint model",
        "--------------",
        "All beacon rows use ONE synthetic compromised host (stable internal_user + nat_ip) so",
        "inter-arrival and volume group cleanly by client. Benign rows use a SMALL subset of",
        "hosts per UTC calendar day (typically 2–5 machines from a fixed pool), so few",
        "machines are active on any given day; membership can change across days.",
        "",
        "C2 target IPs: hostname is stable; udm.target.ip rotates only within the small edge",
        f"pool above. Per UTC day, ~{int(C2_PRIMARY_EDGE_WEIGHT * 100)}% of beacons reuse the same",
        "primary edge IP for that day; the rest pick another IP from the pool (CDN / LB style).",
        "",
        "Model",
        "-----",
        "Beacons are placed on a simple clock: starting at the window start, each next beacon",
        "time is previous time + (delay + U) where U is uniform on [-jitter_s, jitter_s].",
        "Timestamps stay within the configured UTC window.",
        "",
        "Benign noise uses random times uniformly across the same window. A separate stream",
        "of benign periodic telemetry-style traffic is also included (small fraction of noise mix).",
        "",
        "Beacon host (synthetic):",
        f"  internal_user: {beacon_internal}",
        f"  udm.principal.nat_ip: {beacon_nat}",
        "",
    ]
    with open(path, "w", newline="\n", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    range_start, range_end = resolve_time_range(args)
    span_s = (range_end - range_start).total_seconds()
    if span_s <= 0:
        raise SystemExit("Log window has zero length.")

    c2_domain = args.c2_domain if args.c2_domain else default_c2_domain()

    machines = build_machine_pool()
    if not machines:
        raise SystemExit("Machine pool is empty; check INTERNAL_USERS / NAT_POOL sizes.")
    compromised = random.choice(machines)
    c2_edge_ips = [random_public_ipv4() for _ in range(C2_EDGE_IP_COUNT)]
    active_by_day = active_machines_by_day(
        machines, range_start, range_end, args.seed
    )

    beacon_times = generate_beacon_times(
        range_start, range_end, args.beacon_delay, args.beacon_jitter
    )
    noise_count = max(0, args.event_target)

    all_events = []

    # Simulated C2 beacons: one host; target IP from small CDN-style pool
    for ts in beacon_times:
        tip = c2_edge_ip_for_beacon(ts, c2_edge_ips, c2_domain)
        entry = make_entry(
            ts,
            c2_domain,
            args.beacon_protocol,
            target_ip=tip,
            target_asset_ip=tip,
            nat_ip=compromised["nat_ip"],
            internal_user=compromised["internal_user"],
            asn=C2_ASN,
            org=C2_ORG,
        )
        all_events.append(entry)

    # Benign noise + small periodic mix (80/20); few machines active per UTC day
    for _ in range(noise_count):
        ts = range_start + timedelta(seconds=random.uniform(0, span_s))
        if ts > range_end:
            ts = range_end
        if random.random() < 0.8:
            domain, proto = random.choice(NOISE_DOMAINS)
        else:
            domain, proto = random.choice(PERIODIC_DOMAINS)
        m = pick_machine_for_benign_ts(ts, active_by_day)
        if m is None:
            m = random.choice(machines)
        entry = make_entry(
            ts,
            domain,
            proto,
            nat_ip=m["nat_ip"],
            internal_user=m["internal_user"],
        )
        all_events.append(entry)

    all_events.sort(key=lambda x: x["timestamp"])

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_events[0].keys())
        writer.writeheader()
        writer.writerows(all_events)

    doc_path = args.beacon_doc if args.beacon_doc else default_beacon_doc_path(args.output)
    write_beacon_explanation(
        doc_path,
        range_start,
        range_end,
        c2_domain,
        args.beacon_delay,
        args.beacon_jitter,
        args.beacon_protocol,
        len(beacon_times),
        noise_count,
        args.output,
        c2_edge_ips,
        compromised["internal_user"],
        compromised["nat_ip"],
    )

    total = len(all_events)
    print(
        "Generated %s events -> %s; beacon explanation -> %s"
        % (total, args.output, doc_path)
    )

if __name__ == "__main__":
    main()
