# Port Scanner: Full Project Report

---

## 1. Network Protocol Analysis

### 1.1 Host Discovery Protocol

Host discovery uses **two protocols** depending on available tools:

**ARP (Address Resolution Protocol): preferred on LAN** (`discovery.py → _arp_sweep`)
- Operates at Layer 2 (Ethernet), below IP
- Sends a broadcast frame (`ff:ff:ff:ff:ff:ff`) asking "who has this IP?"
- Every machine on the local network that owns the requested IP replies with its MAC address
- Traffic pattern: a burst of ARP requests (one per IP in the subnet), followed by ARP replies from active hosts
- Limitation: only works on the local network segment (cannot cross routers)

**ICMP Ping: fallback** (`discovery.py → _icmp_sweep`)
- Operates at Layer 3 (IP)
- Sends an ICMP Echo Request to each host; active hosts reply with an ICMP Echo Reply
- Traffic pattern: one ICMP packet per host, replies come back from live machines
- Limitation: some firewalls block ICMP, causing false negatives (host appears down but is actually up)

**What the traffic looks like in Wireshark:**
- ARP: rows showing `Who has 192.168.1.X? Tell 192.168.1.Y` → `192.168.1.X is at aa:bb:cc:dd:ee:ff`
- ICMP: rows showing `Echo (ping) request` → `Echo (ping) reply`, with TTL values visible

---

### 1.2 Connection to an Open Port (TCP 3-Way Handshake)

When the scanner connects to an **open** port, the full TCP handshake completes:

```
Scanner                    Target
  |── SYN ──────────────────>|     Step 1: "I want to connect"
  |<───────────── SYN-ACK ──|     Step 2: "OK, I accept"
  |── ACK ──────────────────>|     Step 3: "Connection established"
```

- **TCP connect mode** (`scan_port_connect`): the OS kernel completes all 3 steps via `connect_ex()`. The connection is fully established, then closed with a FIN.
- **SYN scan mode** (`scan_port_syn`): only the SYN is sent. When the SYN-ACK comes back, the scanner immediately sends a RST (reset) to tear down the half-open connection: the handshake is never completed.

**In Wireshark:** you see three packets (SYN → SYN-ACK → ACK) for TCP connect, or two packets (SYN → SYN-ACK) followed by a RST for SYN scan. The SYN flag appears as `[S]`, SYN-ACK as `[S.]`, ACK as `[.]`, RST as `[R]`.

---

### 1.3 Connection to a Closed Port

When the scanner connects to a **closed** port:

```
Scanner                    Target
  |── SYN ──────────────────>|     Step 1: "I want to connect"
  |<───────────────── RST ──|     Immediate rejection: "Nothing is listening here"
```

- The target immediately replies with a **RST** (Reset) packet
- There is no handshake: the connection is refused in a single round-trip
- In the code: `connect_ex()` returns `ECONNREFUSED` (errno 111 on Linux, 10061 on Windows)

**Difference from open port:** an open port replies SYN-ACK (accepting), a closed port replies RST (rejecting). Both reply instantly. A **filtered** port is different: it produces **no reply at all** (timeout), meaning a firewall is silently dropping the packets.

---

### 1.4 Scanning Pattern: What Makes It Recognizable

A port scan is identifiable by several characteristics visible in Wireshark:

1. **Volume**: hundreds or thousands of SYN packets from the same source in a short time span
2. **Sequential or near-sequential ports**: even with randomization, statistical analysis reveals that all ports in a range are being probed
3. **No data exchange**: SYN packets are sent but no application data follows: connections are opened and immediately closed (or reset)
4. **Uniform timing**: packets arrive at regular intervals (especially visible with rate-limiting enabled)
5. **Half-open connections** (SYN scan): SYN → SYN-ACK → RST pattern is a classic signature: legitimate clients complete the handshake, scanners don't

**Our scanner's stealth features** attempt to reduce detectability:
- `--randomize`: shuffles port order so the scan doesn't hit ports 1, 2, 3, 4... sequentially
- `--max-rate`: limits packets per second (e.g. 2 pkt/s) to blend with normal traffic
- `--jitter`: adds random delay variation so timing isn't perfectly regular
- `--delay`: introduces a fixed pause between probes
- SYN scan mode: avoids completing the handshake, so the connection is never logged by the target application (only by the kernel/firewall)

Despite these measures, a well-configured IDS (Intrusion Detection System) will still detect the scan by correlating the number of distinct ports probed from a single source.

---

## 2. Design Report

### 2.1 Code Structure

The project follows a **modular architecture** with clear separation of concerns:

```
network-port-scanner/
├── main.py          → Orchestrator: argument parsing, input validation, scan loop
├── cli.py           → Interactive wizard: step-by-step interface for non-experts
├── scanner.py       → Scan engine: all network-level operations
├── output.py        → Export layer: all result formatting and file writing
├── discovery.py     → Host discovery: ARP sweep and ICMP ping
└── tests/           → Unit tests (76 tests)
    ├── test_scanner.py
    ├── test_main.py
    ├── test_output.py
    ├── test_sanitisation.py
    └── test_discovery.py
```

**Why this structure:**

- **`scanner.py`** handles everything that touches the network (sockets, raw packets). Isolating network code makes it testable with mocks and keeps other modules network-free.
- **`output.py`** handles everything that touches presentation (console summary, file exports). One module responsible for "how results look": whether JSON, CSV, HTML, XML, or terminal output.
- **`main.py`** is the orchestrator. It validates inputs, calls the scanner, enriches results (banners, versions, OS, firewall), then hands them to `output.py`. It knows *when* to do things, not *how*.
- **`cli.py`** is a separate entry point for users who don't want to memorize command-line flags. It asks questions step by step and builds the same parameters that `main.py` accepts.
- **`discovery.py`** is isolated because host discovery is an independent pre-scan step that uses different protocols (ARP/ICMP vs TCP).

### 2.2 Libraries Used

#### Standard Library (built-in)

| Library | File(s) | Purpose |
|---|---|---|
| `socket` | `scanner.py` | Create TCP connections to scan ports and read banners |
| `argparse` | `main.py` | Parse command-line arguments (`--target`, `--ports`, etc.) |
| `ipaddress` | `scanner.py`, `main.py`, `discovery.py` | Validate IP addresses and CIDR networks |
| `concurrent.futures` | `scanner.py`, `discovery.py` | `ThreadPoolExecutor`: run scans in parallel (multi-threading) |
| `threading` | `scanner.py` | `Lock` for thread-safe rate limiting |
| `time` | `main.py`, `scanner.py` | Scan timer, delays between packets |
| `random` | `scanner.py` | Shuffle port order (stealth mode), add jitter |
| `errno` | `scanner.py` | OS error codes (`ECONNREFUSED`) to identify closed ports |
| `os` | `cli.py` | Detect root privileges (`geteuid`) to choose SYN vs TCP connect |
| `sys` | `main.py` | Exit with return codes |
| `logging` | `main.py` | Structured logging |
| `pathlib` | `main.py`, `output.py` | File path manipulation |
| `typing` | all | Type hints (`Dict`, `List`, `Optional`, `Callable`) |
| `json` | `output.py` | Export results to JSON |
| `csv` | `output.py` | Export results to CSV |
| `html` | `output.py` | Escape special characters for safe HTML output |
| `xml.etree.ElementTree` | `output.py` | Generate Nmap-compatible XML reports |
| `datetime` | `output.py` | Timestamps in reports |
| `platform` | `discovery.py` | Detect OS to adapt the `ping` command (Linux/macOS/Windows) |
| `subprocess` | `discovery.py` | Execute the system `ping` command as ICMP fallback |

#### External Libraries (installed via pip)

| Library | File(s) | Purpose |
|---|---|---|
| `scapy` | `scanner.py`, `discovery.py` | Send/receive raw packets: SYN scan, OS fingerprinting (TTL analysis), firewall type detection, ARP sweep. Requires sudo/admin |
| `tqdm` | `scanner.py` | Progress bar during scan (optional: scanner works without it) |
| `pytest` | `tests/` | Test framework |

### 2.3 Wireshark Observations Before Building

Analyzing network traffic in Wireshark before writing the scanner informed several design decisions:

- **TCP connect leaves a full trace**: observing SYN → SYN-ACK → ACK → FIN showed that every connection is logged by the target. This motivated implementing the SYN scan alternative.
- **RST vs timeout**: observing that closed ports reply instantly (RST) while filtered ports produce silence (timeout) led to the three-state model: `open`, `closed`, `filtered`.
- **ARP is faster than ICMP on LAN**: ARP responses arrive in < 1ms while ICMP ping can take 100ms+. This justified making ARP the preferred discovery method.
- **Banner behavior varies**: some services (SSH, FTP, SMTP) send their banner immediately on connection, while others (HTTP) wait for a request. This led to the two-phase `grab_banner()` design: passive recv first, then send `\r\n` if nothing received.
- **Firewall types are distinguishable**: DROP firewalls produce complete silence (timeout), while REJECT firewalls send back an ICMP "port unreachable" message. This distinction is implemented in `detect_firewall()`.

---

## 3. Testing Report

### 3.1 Test Suite Overview

The project has **76 unit tests** organized across 5 test files, all passing:

```
tests/test_scanner.py     : 25 tests (scan engine, banners, OS/version/firewall detection)
tests/test_sanitisation.py: 23 tests (input validation: ports, targets, file paths, threads)
tests/test_output.py      :  9 tests (export formats: TXT, JSON, CSV, HTML, XML)
tests/test_main.py        :  4 tests (CLI integration: basic run, JSON output, SYN fallback, threads)
tests/test_discovery.py   :  3 tests (host discovery: ICMP sweep, single IP, return type)
```

All tests run in **~2 seconds** using mocked network calls (no real network traffic during tests).

### 3.2 What Was Tested

**Open ports:**
- `scan_port_connect` returns `"open"` when `connect_ex()` returns 0
- `scan_port_syn` returns `"open"` when a SYN-ACK (flags `0x12`) is received
- Banner grabbing correctly reads service identification strings
- Service version detection extracts `Server:` header from HTTP responses

**Closed ports:**
- `scan_port_connect` returns `"closed"` when `connect_ex()` returns `ECONNREFUSED`
- `scan_port_syn` returns `"closed"` when a RST (flags `0x04`) is received
- Firewall detection returns `"closed"` on RST (no firewall blocking)

**Filtered ports:**
- `scan_port_connect` returns `"filtered"` on timeout or `OSError`
- `scan_port_syn` returns `"filtered"` when `sr1()` returns `None` (no response)
- Firewall detection distinguishes `"filtered-silent"` (DROP, no response) from `"filtered-active"` (REJECT, ICMP reply)

**Edge cases:**
- Port 0 → rejected (`ValueError`)
- Port 65536 → rejected (`ValueError`)
- Negative port → rejected
- Empty target → rejected
- Target with forbidden characters (`;`, `|`, etc.) → rejected
- Hostname longer than 253 characters → rejected
- Reversed port range (`85-80`) → auto-corrected to `80-85`
- Duplicate ports → deduplicated
- `--threads 0` or `--threads -1` → error returned before scan starts
- Output path with directory traversal (`../../etc/passwd.txt`) → rejected
- Invalid file extension → rejected (only `.txt`, `.json`, `.csv`, `.html`, `.xml` allowed)
- SYN scan without scapy installed → graceful fallback to TCP connect
- SYN scan without root privileges → returns `"filtered"` with a warning

**Output formats:**
- TXT: one port per line, correct formatting
- JSON: valid JSON structure, string keys
- CSV: correct headers (`port, status, service, banner, os, version, firewall`)
- HTML: valid HTML with statistics, special characters escaped (XSS prevention)
- XML: Nmap-compatible structure, special characters escaped, firewall element present when applicable

### 3.3 Test Results

```
======================== 76 passed in 2.33s ========================
```

All 76 tests pass. No failures, no warnings.

---

## 4. Ethics & Detection Report

### 4.1 Testing Environment: Lab Only

All testing was performed exclusively in a **controlled lab environment**:
- **Localhost** (`127.0.0.1`): scanning the local machine's own ports
- **Private LAN** (`192.168.x.x`): scanning devices on the local home/lab network that we own or have explicit permission to scan
- **No external targets**: no public IP addresses, no third-party servers, no production systems were scanned at any point

The unit tests use **mocked network calls**: no actual packets are sent during testing. The `socket.connect_ex()`, `sr1()`, and other network functions are replaced with test doubles that simulate open, closed, and filtered responses.

### 4.2 What Port Scanning Looks Like from the Defender's Perspective

From a network defender's point of view (monitoring with Wireshark, IDS, or firewall logs), a port scan produces these signatures:

**TCP Connect scan:**
- Hundreds of complete TCP handshakes (SYN → SYN-ACK → ACK → FIN) from a single source IP in a short window
- Each connection is logged at the application level (e.g. Apache access logs, SSH auth logs)
- The source IP is fully visible: no spoofing possible with TCP connect

**SYN scan:**
- Hundreds of SYN packets from a single source, with most connections never completing (SYN → SYN-ACK → RST)
- Not logged by most applications (the TCP handshake never completes), but visible in kernel-level logs and firewall/IDS
- The RST sent after SYN-ACK is a classic scanner signature: legitimate clients don't behave this way

**Host discovery (ARP):**
- A burst of ARP "who has?" requests covering an entire subnet: a clear sign of network reconnaissance
- Visible on any machine in the same broadcast domain

**Detection indicators (what an IDS flags):**
1. High number of distinct destination ports from one source (horizontal scan)
2. SYN packets with no follow-up data exchange
3. Connections that are immediately reset after SYN-ACK
4. Sequential or patterned port numbers (even randomized scans probe all ports eventually)
5. Unusual TTL values or packet sizes from the scanning host

### 4.3 Why Authorization Matters

**Legal perspective:**
- Port scanning without authorization is **illegal** in most jurisdictions (Computer Fraud and Abuse Act in the US, similar laws in the EU)
- Even a "harmless" SYN scan constitutes unauthorized access to a computer system if performed without permission
- The scanner operator's IP is visible in every packet: there is no anonymity in port scanning

**Technical perspective:**
- A scan can crash vulnerable services (especially on embedded devices, IoT, or legacy systems)
- High-speed scanning can saturate a network link or trigger rate-limiting that affects legitimate users
- Firewall/IDS alerts triggered by a scan may cause an incident response team to investigate, wasting resources

**Ethical perspective:**
- Scanning is a **reconnaissance** technique: the first step in an attack chain
- Even with good intentions, scanning someone else's network without permission is a violation of trust
- Always obtain **written authorization** before scanning any network you don't own

**Our approach:**
- All scans target `127.0.0.1` (localhost) or private LAN IPs we control
- Tests use mocks: zero network traffic
- The tool is designed for **authorized security auditing** only

---

## 5. Additional Features

Beyond the basic port scanner requirements, the following features were implemented:

### 5.1 SYN Scan (Half-Open Scan)
- Sends raw SYN packets via scapy instead of completing the TCP handshake
- The connection is never fully established → not logged by target applications
- Automatically sends RST after receiving SYN-ACK to clean up half-open connections
- Auto-detected based on root privileges (no manual selection needed)
- Falls back gracefully to TCP connect when scapy is unavailable or user lacks root

### 5.2 OS Detection (`--os-detect`)
- Fingerprints the target's operating system using **TTL analysis** from TCP SYN-ACK responses
- TTL ≤ 64 → Linux/Unix, TTL ≤ 128 → Windows, TTL > 128 → Network device
- Probes common ports (80, 443, 22) to obtain a response

### 5.3 Service Version Detection (`--version-detect`)
- Sends protocol-specific probes to identify the software version running on open ports
- HTTP: sends `HEAD / HTTP/1.0` and extracts the `Server:` header
- SMTP: sends `EHLO probe` to trigger the server identification
- SSH/FTP/POP3/IMAP: reads the spontaneous banner (no probe needed)

### 5.4 Firewall Type Detection (`--firewall-detect`)
- Distinguishes between two types of firewall behavior on filtered ports:
  - **filtered-silent**: firewall uses DROP rule: complete silence, no response
  - **filtered-active**: firewall uses REJECT rule: sends back an ICMP "port unreachable" message
- Uses scapy to analyze the response at the packet level

### 5.5 Host Discovery (`--discover`)
- Discovers active hosts on a subnet before scanning their ports
- ARP sweep (preferred on LAN): fast, reliable, Layer 2
- ICMP ping fallback: works across routers, parallelized with ThreadPoolExecutor
- Ping command adapted per OS (Linux `-W` in seconds, macOS `-W` in ms, Windows `-n 1 -w <ms>`)

### 5.6 Stealth / Anti-Detection Features
- `--randomize`: shuffles port order to avoid sequential scanning patterns
- `--max-rate`: true rate limiting (packets/second) with a thread-safe lock
- `--jitter`: random delay variation between probes
- `--delay`: fixed pause between probes

### 5.7 Multiple Export Formats
- `.txt`: plain text, one port per line
- `.json`: structured JSON for programmatic use
- `.csv`: spreadsheet-compatible with full headers
- `.html`: colored report with embedded CSS, statistics, and XSS-safe escaping
- `.xml`: Nmap-compatible format (`<nmaprun>` structure) for integration with tools like Metasploit

### 5.8 Scan Summary (Statistics Generator)
- Displays an analytical summary at the end of every scan
- Shows: total ports scanned, open/closed/filtered breakdown, firewall detail (silent/active), open percentage, execution time
- Correctly handles multi-host scans without overwriting duplicate port numbers

### 5.9 Interactive CLI (`cli.py`)
- Step-by-step wizard for users unfamiliar with command-line flags
- Predefined scan profiles (quick, standard, full, custom)
- Speed presets (fast/normal/slow/stealth) that auto-configure threads, timeout, delay, and rate
- Unicode-safe output with ASCII fallback for Windows terminals
- Recap box showing all parameters before scan launch

### 5.10 Cross-Platform Compatibility
- Windows: `WSAECONNREFUSED` error code support, `geteuid` fallback (always returns non-root), Npcap support for SYN scan
- macOS: ping timeout in milliseconds (`-W`), correct `geteuid` detection
- Linux: ping timeout in seconds (`-W`), full scapy support with sudo
