# Walkthrough: statistics summary

A line-by-line guide to `print_summary()` in `output.py`, which produces the end-of-scan statistics block shown in the terminal.

## What the feature does

A statistics block displayed automatically in the terminal at the end of every scan. Instead of a single line `open: X closed: Y filtered: Z`, the user sees a full summary:

```
--- Scan Summary ---
  Ports scanned   : 1024
  Ports open      : 3
  Ports closed    : 987
  Ports filtered  : 34  (silent: 30, active: 4)
  Open rate       : 0.29%
  Execution time  : 4.87 seconds
```

## Where the code lives

| File | Role |
|---|---|
| `output.py` | Contains `print_summary()`: all the counting and display logic |
| `main.py` | Starts the timer and calls `print_summary()` at the right moment |

## The main function: `print_summary(results, elapsed)`

Located at the bottom of `output.py`.

### Arguments

#### `results`: `Dict[int, dict]`

The main scan dictionary, built in `main.py` after the scan. Each key is a port number, each value is a dict with the following fields:

```python
results = {
    22: {
        "status":  "open",
        "service": "ssh",
        "banner":  "SSH-2.0-OpenSSH_8.9",
        "os":      "Linux/Unix",
        "version": "OpenSSH_8.9",
        "firewall": "filtered-silent"
    },
    80: {
        "status":  "closed",
        "service": "http",
        "banner":  "",
        "os":      "Linux/Unix",
        "version": "",
        "firewall": ""
    },
}
```

`print_summary` receives this dict and iterates over `.values()` to count statuses.

#### `elapsed`: `float`

Scan duration in seconds, computed in `main.py`:

```python
start_time = time.time()
# scan runs here
elapsed = time.time() - start_time
```

`time.time()` returns seconds since the Unix epoch (January 1, 1970). Subtracting gives the exact duration.

## Step by step

### 1. Count open ports

```python
open_count = 0
for info in results.values():
    if info["status"] == "open":
        open_count += 1
```

Iterates over all dict values. Increments the counter every time the status is `"open"`.

### 2. Count closed ports

Same logic with `"closed"`.

### 3. Count filtered ports

```python
filtered_count = sum(
    1 for info in results.values()
    if info["status"] in ("filtered", "filtered-silent", "filtered-active")
)
```

In practice `info["status"]` always equals `"filtered"`. That value is produced by `scan_range_threaded`. The silent/active detail is stored in `info["firewall"]`, not in `info["status"]`. The `in` check above is defensive: it handles future code paths where the status itself could carry the detail.

### 4. Firewall silent vs active breakdown

```python
firewall_silent = 0
firewall_active = 0
for info in results.values():
    firewall = info.get("firewall", "")
    if firewall == "filtered-silent":
        firewall_silent += 1
    elif firewall == "filtered-active":
        firewall_active += 1
```

`info.get("firewall", "")` is used instead of `info["firewall"]` because the `firewall` field is only populated when `--firewall-detect` is enabled. With `[]`, the code would raise `KeyError` on missing keys. With `.get(..., "")`, missing keys return `""`, no crash.

These two counters are only displayed when at least one is greater than zero:

```python
if firewall_silent or firewall_active:
    print(f"  (silent: {firewall_silent}, active: {firewall_active})", end="")
```

### 5. Total and percentage

```python
total = len(results)
percentage = (open_count / total * 100) if total > 0 else 0.0
```

`len(results)` returns the number of keys in the dict, which equals the number of ports scanned. The `if total > 0 else 0.0` guard protects against division by zero: if the scan ever returns an empty dict (no ports), we do not divide by zero.

### 6. Display

```python
print(f"  Open rate       : {percentage:.2f}%")
print(f"  Execution time  : {elapsed:.2f} seconds")
```

`:.2f` formats the float to two decimal places. Without it, Python would print `0.2929292929...%`. With `:.2f`, the output is `0.29%`.

## The timer in `main.py`

The timer starts **after** DNS resolution and host discovery, but **before** the port scan. It measures only the scan time plus enrichment (banners, versions, firewall). Discovery time (`--discover`) is intentionally excluded.

```python
start_time = time.time()

raw = scan_range_threaded(...)
# enrichment: banners, versions, firewall

elapsed = time.time() - start_time
print_summary(results, elapsed)
```

## Data flow

```
CLI (main.py or cli.py)
   |
   +-- scan_range_threaded()   ->  raw = {port: "open"/"closed"/"filtered"}
   |       (scanner.py)
   |
   +-- get_service_name()         adds "service" to each port
   +-- grab_banner()              adds "banner" (if --banner)
   +-- detect_service_version()   adds "version" (if --version-detect)
   +-- detect_os()                adds "os" (if --os-detect)
   +-- detect_firewall()          adds "firewall" (if --firewall-detect)
            (scanner.py)
   |
   +-- results = {port: {status, service, banner, os, version, firewall}}
                   |
                   v
            print_summary(results, elapsed)
                 (output.py)
```

`print_summary` is at the end of the chain: it receives the final enriched dict.

## Why in `output.py` and not elsewhere?

`output.py` owns everything related to result presentation: JSON, CSV, HTML, XML writers, and now the console summary. One file is responsible for "how results are shown".

`main.py` keeps its single responsibility: orchestration ("when to do what"), not display.
