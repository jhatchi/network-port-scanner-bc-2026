# Architecture

Technical reference for the Network Port Scanner. The project is organized into **6 Python modules** that work together. Each module has a clear, single responsibility.

## Modules

### `scanner.py`: the engine

The core of the project. Contains all scanning and network analysis logic.

**Public functions:**

- `scan_port_connect(ip, port, timeout)` returns `"open"` | `"closed"` | `"filtered"`. Standard TCP connection, cross-platform.
- `scan_port_syn(ip, port, timeout)` returns `"open"` | `"closed"` | `"filtered"`. Raw SYN packet via scapy (requires sudo). Sends RST after SYN-ACK to close half-open connections.
- `scan_range_threaded(ip, ports, scan_fn, timeout, delay, max_workers, randomize, max_rate, jitter)` returns dict. Launches hundreds of scans in parallel via `ThreadPoolExecutor`.
- `get_service_name(port)` returns the service name (`"http"`, `"ssh"`, etc.). Checks a built-in dictionary of 77 services first, then falls back to `socket.getservbyport()`.
- `grab_banner(ip, port, timeout)` returns the first response line from the service. Passive recv first (`min(0.5, timeout)`), then `\r\n` probe only if nothing was received.
- `detect_service_version(ip, port, service_name, timeout)` returns the extracted version. Probes HTTP HEAD, SMTP EHLO, MySQL greeting, DNS version.bind, VNC RFB, Redis INFO, IRC, PostgreSQL, and more.
- `detect_os(ip, timeout)` returns `"Linux/Unix"` | `"Windows"` | `"Network device"` | `"unknown"`. TTL fingerprinting (requires scapy + sudo). Sends RST after SYN-ACK.
- `detect_firewall(ip, port, timeout)` returns `"open"` | `"closed"` | `"filtered-silent"` | `"filtered-active"`. Distinguishes silent DROP from active ICMP REJECT (requires scapy + sudo).
- `resolve_target(target)`: single DNS resolution before the scan starts.

**Independence:** does not depend on any other project file. Usable as a standalone library.

**Windows compatibility:** `geteuid` via `getattr(os, "geteuid", lambda: 1)()`. `ECONNREFUSED` via `_ECONNREFUSED_CODES` (includes `WSAECONNREFUSED`).

### `discovery.py`: host detection

Before scanning ports on a machine, identify which machines are alive on the network.

- Sends ARP broadcast requests to detect machines on the local network (`_arp_sweep`, via scapy).
- Falls back to parallel ICMP pings on all addresses in a subnet (`_icmp_sweep`).
- Returns the list of responding IPs (`discover_hosts`).

**Cross-platform ping:**

- Linux: `ping -c 1 -W <seconds>`
- macOS: `ping -c 1 -W <milliseconds>`
- Windows: `ping -n 1 -w <milliseconds>`

Called by `main.py` only when `--discover` is enabled.

### `output.py`: results export

Writes scan results to file. All formats include the detected OS in the header.

- `.txt`: plain text, one port per line with status, service, banner, version, CVEs.
- `.json`: structured payload with `meta` (target, scan_type, os, date) and `ports`.
- `.csv`: spreadsheet-compatible (columns: port, status, service, banner, os, version, firewall, vulns).
- `.html`: colored visual report with stats table, OS in header, CVE badges with CSS tooltips, embedded CSS (green = open, red = closed, gray = filtered).
- `.xml`: Nmap and Metasploit compatible (`<nmaprun>/<host>/<os>/<ports>/<port>/<vulnerabilities>`), built with `xml.etree.ElementTree`.

Called by `main.py` at the end of the scan. Multi-host scans produce one file per host.

### `vuln_analyzer.py`: vulnerability analysis

Queries the NVD (NIST) API for known CVEs based on detected service versions.

- `parse_banner(banner)`: extracts `(software, version)` via dynamic regex (SSH-specific pattern first, then generic `software/version` pattern).
- `analyze_vulnerabilities(banner)`: queries the NVD API for CVEs with CVSS >= 7.0, sorted by severity.
- In-memory cache (`_CVE_CACHE`) avoids redundant API calls within a scan.
- Returns `[{"id": "CVE-...", "cvss": 9.8, "description": "..."}]`.
- Logging via `logging.debug` / `logging.warning` (no `print`, to avoid polluting the tqdm progress bar).

Called by `main.py` when `--vuln-scan` is enabled.

### `main.py`: the orchestrator

The main entry point. Parses CLI arguments and coordinates the other modules.

**Pipeline:**

1. Validate user input: `validate_target()` (IPv4, IPv6, CIDR, hostname), `validate_port()`, `validate_output_file()`, `parse_ports()`.
2. Resolve hostname to IP once (`resolve_target`).
3. Call `discovery.py` if `--discover` is active.
4. Call `scanner.py` to scan ports in parallel.
5. Enrich results: service name, banner, version, OS, firewall type.
6. Call `vuln_analyzer.py` if `--vuln-scan` is active.
7. Print statistics summary in the terminal (no per-port output, full detail goes to the report file).
8. Call `output.py`. One file per host for multi-host scans.

**Results structure:**

```python
results[port] = {
    "status":   "open" | "closed" | "filtered",
    "service":  "ssh" | "http" | ...,
    "banner":   "SSH-2.0-OpenSSH_8.9" | "",
    "os":       "Linux/Unix" | "Windows" | "unknown" | "",
    "version":  "nginx/1.18.0" | "",
    "firewall": "filtered-silent" | "filtered-active" | "",
    "vulns":    [{"id": "CVE-...", "cvss": 9.8, "description": "..."}] | [],
}
```

**CLI options:**

| Option | Description |
|---|---|
| `--target` | IP, IPv6, hostname or CIDR |
| `--ports` | `22,80,443` or `1-1024` or any combination |
| `--scan-type` | `connect` (default) or `syn` |
| `--output` | `.txt`, `.json`, `.csv`, `.html`, `.xml` |
| `--threads` | Parallel connections (default 100) |
| `--timeout` | Per-port timeout in seconds |
| `--banner` | Read banners from open services |
| `--version-detect` | Detect version via protocol probe |
| `--os-detect` | Detect OS via TTL fingerprinting (sudo required) |
| `--firewall-detect` | Distinguish DROP vs REJECT (sudo required) |
| `--vuln-scan` | Look up known CVEs via NVD API |
| `--discover` | Discover active hosts before scanning |
| `--randomize` | Shuffle port order |
| `--max-rate` | Maximum global rate in packets per second |
| `--delay` | Fixed pause between ports |
| `--jitter` | Random delay between ports |

**Imports:** `scanner`, `output`, `discovery` (optional at runtime), `vuln_analyzer` (optional at runtime).

### `cli.py`: the interactive interface

A user-friendly layer on top of `main.py`. Instead of typing CLI flags, the user answers questions step by step.

- Asks: target, profile, speed, options, report format.
- Translates simple choices ("Fast") into technical parameters (`threads=400`, `timeout=0.3`).
- Root users can choose between SYN and TCP connect modes. Non-root defaults to TCP connect.
- Offers advanced options: discovery, banners, service version, firewall, OS.
- Safe Windows display via `_print_safe` (ASCII fallback when the terminal does not support UTF-8).
- Builds the argument list and calls `main.py`.

**Imports:** `main` only (via `from main import main`).

## Interaction diagram

```
User
  |
  +-- python cli.py             ->  cli.py
  |                                   |
  |                                   v
  +-- python main.py [args]     ->  main.py
                                      |
                  +----------+--------+---------+
                  v          v        v         v
              scanner.py  discovery  output  vuln_analyzer
                          (.py)      (.py)   (.py)
```

**Full scan flow with all options enabled:**

```
cli.py (optional)
  +-> main.py
        +-> validate_target() / parse_ports()        [validation]
        +-> resolve_target()                          [scanner.py: single DNS]
        +-> discover_hosts()                          [discovery.py: if --discover]
        +-> scan_range_threaded()                     [scanner.py: parallel scan]
        |     +-> scan_port_connect() / scan_port_syn()  [per port]
        +-> detect_os()                               [scanner.py: if --os-detect]
        +-> get_service_name()                        [scanner.py: enrichment]
        +-> grab_banner()                             [scanner.py: if --banner]
        +-> detect_service_version()                  [scanner.py: if --version-detect]
        +-> detect_firewall()                         [scanner.py: if --firewall-detect, filtered ports]
        +-> analyze_vulnerabilities()                 [vuln_analyzer.py: if --vuln-scan]
        +-> write_output()                            [output.py: result file(s)]
```

## Dependency summary

| File | Imports | Imported by |
|---|---|---|
| `scanner.py` | `socket`, `errno`, `re`, `threading`, `concurrent.futures`, `scapy` (optional) | `main.py` |
| `discovery.py` | `subprocess`, `ipaddress`, `platform`, `concurrent.futures`, `scapy` (optional) | `main.py` |
| `output.py` | `csv`, `json`, `html`, `xml.etree.ElementTree`, `datetime` | `main.py` |
| `vuln_analyzer.py` | `requests`, `re`, `logging`, `time` | `main.py` |
| `main.py` | `scanner`, `output`, `discovery`, `vuln_analyzer`, `argparse`, `logging` | `cli.py` |
| `cli.py` | `main`, `os` | (entry point) |

## Scan status semantics

| Status | Meaning |
|---|---|
| `open` | TCP handshake completed |
| `closed` | Connection refused (RST received) |
| `filtered` | Timeout, or host unreachable |
| `filtered-silent` | Timeout, DROP firewall (requires `--firewall-detect` + sudo) |
| `filtered-active` | ICMP response, REJECT firewall (requires `--firewall-detect` + sudo) |

## Interactive CLI profiles

| Profile | Ports | Use case |
|---|---|---|
| Quick scan | 21, 22, 23, 25, 53, 80, 111, 139, 443, 445, 512-514, 1099, 1524, 2049, 2121, 3306, 3389, 5432, 5900, 6000, 6667, 8009, 8080, 8180 (26 ports) | Common services |
| Standard scan | 1-1024 | General audit |
| Full scan | 1-65535 | Exhaustive (slow) |
| Custom | User-defined | Specific ports |

## Interactive CLI speeds

| Speed | Threads | Timeout | Delay | Max rate | Randomize |
|---|---|---|---|---|---|
| Fast (LAN) | 400 | 0.3 s | 0 | n/a | no |
| Normal | 200 | 0.5 s | 0 | n/a | no |
| Slow (discreet) | 20 | 2.0 s | 0.1 s | n/a | no |
| Stealth (anti-IDS) | 5 | 3.0 s | 0 | 2 pkt/s | yes |

## Dependencies

```bash
pip install -r requirements.txt
```

- `tqdm`: progress bar (optional)
- `scapy`: SYN scan, OS/firewall detection, ARP discovery (requires sudo/admin and Npcap on Windows)
- `requests`: HTTP requests to the NVD API (`vuln_analyzer.py`)
- `pytest`: test runner

## Deferred features

Documented in `docs/design-history/implementation-plan.md`:

- `--ttl <value>`: custom TTL in SYN packets (TTL-based IDS evasion)
- `--decoys 192.168.1.5,192.168.1.6`: decoy source IPs (requires scapy + sudo)
- `--fragment`: IP packet fragmentation to evade IDS (requires scapy + sudo)
