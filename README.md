# Iterative DNS Resolver

A Python implementation of an iterative DNS resolver built from scratch over raw UDP sockets (`SOCK_DGRAM`). The resolver constructs wire-format DNS queries, parses binary responses (including RFC 1035 label compression), and traverses the DNS hierarchy from a root server down to authoritative nameservers without relying on external DNS libraries.

## Project Structure

* `resolver.py` — Main CLI entry point and core DNS protocol implementation (wire encoding/decoding, UDP socket transport with retries, response parsing, and iterative resolution).
* `dns_model.py` — Data models (`DNSBase`, `DNSQuestion`, `DNSRecord`, `DNSMessage`) and deterministic `dig`-style output formatting.
* `Makefile` — Helper target (`make topo`) to launch the Mininet network testbed (`testbed/topo.py`).
* `mark.txt` — Coursework task checklist tracking network topology setup and resolver implementation milestones.

## Features

* **Wire-Format Serialization & Parsing:** Packs and unpacks 12-byte DNS headers, question sections, and resource records (`A`, `NS`, `CNAME`, `MX`, `TXT`) using `struct`.
* **RFC 1035 Label Compression:** Recursively resolves `0xC0` compression pointer offsets in both owner names and `NS`/`CNAME`/`MX` `RDATA` fields.
* **Iterative Hierarchy Traversal:** Queries a root nameserver with Recursion Desired (`RD=0`) disabled, matches `AUTHORITY` `NS` referrals to `ADDITIONAL` glue `A` records (case-insensitively), and falls back to resolving glueless nameservers recursively from the root.
* **Resilience & Error Handling:** Retries timed-out UDP packets up to 5 times per server, fails over across multiple glue IPs, validates transaction IDs, guards against referral loops (max 15 hops), and cleanly reports `NXDOMAIN` (`RCODE 3`), `NODATA`, and unreachable/invalid glue servers.

## Requirements

* **Python 3.9+** (standard library only; zero third-party dependencies)
* **Mininet** (required only when running the local virtual network testbed via `make topo`)

## CLI Options

| Argument / Flag | Description |
| :--- | :--- |
| `name` | Target domain name to query (e.g., `haris.sccm5310.lab.`) |
| `type` | Record type: `A`, `NS`, `CNAME`, `MX`, or `TXT` |
| `--root ADDRESS` | Start iterative resolution at this root server IP (mutually exclusive with `--server`) |
| `--server ADDRESS` | Send a single non-recursive query directly to this server IP (mutually exclusive with `--root`) |
| `--timeout SECONDS` | Socket timeout per UDP attempt in seconds (default: `2.0`) |
| `--trace` | Print each query sent and referral hop followed during iterative resolution |

## Running the Mininet Testbed

Launch the virtual DNS network topology:

```bash
make topo
```

Once inside the `mininet>` prompt, execute queries from `host` using the testbed's root server (`10.0.0.2`).

## Example & Verification Queries

### 1. Standard Iterative Resolution (`A`, `TXT`, `NS`)

Resolve records from the root server (`10.0.0.2`) down through the TLD (`10.0.1.2`) and authoritative (`10.0.2.2`) servers:

```bash
# Standard A record lookup
host python3 resolver.py --root 10.0.0.2 haris.sccm5310.lab. A

# With --trace to inspect every query and referral hop
host python3 resolver.py --trace --root 10.0.0.2 haris.sccm5310.lab. A

# Query TXT and NS records
host python3 resolver.py --trace --root 10.0.0.2 haris.sccm5310.lab. TXT
host python3 resolver.py --trace --root 10.0.0.2 sccm5310.lab. NS
```

### 2. Direct Single-Server Query (`--server`)

Query a specific nameserver directly without following referrals:

```bash
host python3 resolver.py --server 10.0.2.2 haris.sccm5310.lab. A
```

### 3. Edge Cases & Error Handling

Verify how the resolver handles non-existent domains, missing record types, and unresponsive servers:

```bash
# NXDOMAIN (RCODE 3): Non-existent domain
host python3 resolver.py --trace --root 10.0.0.2 nonexistent.sccm5310.lab. A

# NODATA (NOERROR, ANSWER: 0): Valid domain with no matching record type
host python3 resolver.py --trace --root 10.0.0.2 haris.sccm5310.lab. CNAME

# Timeout / Unreachable Server: Fast failure test with 0.5s timeout
host python3 resolver.py --trace --timeout 0.5 --root 10.0.0.99 haris.sccm5310.lab. A
```

### 4. Standalone Usage (Outside Mininet)

```bash
python3 resolver.py example.com A --root 198.41.0.4 --trace
```
