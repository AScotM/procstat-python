# procstat-python

Linux process forensics, live observability, and ANSI truecolor terminal art-technology, implemented in a single Python standard-library file.

**Version:** 2.1.0  
**License:** GNU GPLv3  
**Platform:** Linux, Python 3.9+ recommended  
**Dependencies:** Python standard library only

## Overview

`procstat-python` reads kernel process telemetry directly from `/proc` to build a live census of processes and optionally their threads. It provides CPU and memory views, process trees, scheduling and I/O statistics, process lifecycle tracking, baseline comparison, and a colorful terminal constellation representing CPU activity and resident memory.

It is intended for experiments, diagnosis, and terminal-based exploration of process behavior. It does not require root, although permissions and procfs mount options may restrict access to individual processes.

## Installation

```bash
mkdir -p ~/garage/procstat-python
cd ~/garage/procstat-python
cp /path/to/main.py .
chmod +x main.py
python3 main.py --help
```

No `pip install` is necessary.

## Quick start

```bash
python3 main.py
python3 main.py top --sort cpu --limit 30
python3 main.py top --sort mem --limit 20
python3 main.py summary
python3 main.py tree --limit 100 --depth 12
python3 main.py tree --threads --limit 150
python3 main.py topology --palette violet --color always
python3 main.py watch --interval 2 --count 10
python3 main.py --watch 2
python3 main.py inspect --pid 1
python3 main.py inspect --pid 1 --threads
```

## Commands

| Command | Function |
| --- | --- |
| `top` | Sorted process and thread table, the default |
| `tree` | Hierarchical process tree with optional threads |
| `summary` | State census and top consumers of CPU, RSS, I/O, and threads |
| `topology` | ANSI truecolor bars mapping process CPU and RSS |
| `watch` | Repeated monitoring with CPU deltas and lifecycle events |
| `snapshot` | Save a JSON process snapshot |
| `baseline` | Alias of snapshot for comparison workflows |
| `diff` | Compare a saved snapshot with the current process census |
| `inspect` | Detailed statistics for one PID |

## Snapshot and comparison

```bash
python3 main.py baseline --output before.json
sleep 30
python3 main.py diff --baseline before.json --limit 50
python3 main.py diff --baseline before.json --format json > changes.json
python3 main.py snapshot --output after.json
```

A process identity consists of PID, thread ID, and kernel start ticks. This helps avoid falsely interpreting PID reuse as continuous activity. The diff reports new, exited, and persistent processes, along with resident memory, cumulative CPU-time, and thread-count changes. CPU-time differences are **not** interval CPU percentages.

## Exports

```bash
python3 main.py top --format json > processes.json
python3 main.py top --format jsonl > processes.jsonl
python3 main.py top --format csv > processes.csv
python3 main.py snapshot --output snapshot.json
python3 main.py top --output census.csv
python3 main.py watch --interval 2 --count 20 --output timeline.jsonl
python3 main.py watch --interval 2 --count 20 --output timeline.csv
```

`--output` writes a full snapshot as JSON for ordinary commands, or row-oriented CSV when the filename ends with `.csv`. In watch mode it appends JSONL or CSV observations rather than overwriting earlier samples. Output formats printed on standard output are selected with `--format`.

## Visualization

```bash
python3 main.py topology --palette ocean
python3 main.py topology --palette ember --sort cpu --limit 40
python3 main.py topology --palette forest --sort mem --limit 30
python3 main.py topology --palette violet --color always
```

The palettes are `aurora`, `solar`, `ice`, `ocean`, `ember`, `violet`, `forest`, and `mono`. Color is automatic on interactive terminals; set `--color never` for plain text or `--color always` for ANSI output in pipes. `NO_COLOR` disables automatic coloring.

## Monitoring behavior

The first CPU measurement is a **lifetime average** because no earlier sample exists. Subsequent scans in the same process use deltas of user and system CPU ticks divided by monotonic elapsed time. A process using one full logical CPU reports approximately 100%, so aggregate CPU can exceed 100% on multicore hosts. CPU readings are not normalized by core count.

Thread CPU values are independently measured, but process rows already represent thread-group activity. Do not sum thread rows and process rows together. Thread RSS is reported from process-level status and is **not additive** across threads. Aggregate RSS in the header includes only process rows, although shared pages between different processes can still be counted more than once.

The tool collects `/proc/[pid]/stat`, `status`, `cmdline`, and optionally `io`; for threads it reads `/proc/[pid]/task/[tid]/stat`, `status`, and `io`. Reads can fail when processes exit during sampling or access is restricted.

I/O delta columns measure differences between observations and are zero/empty on initial scans. Some I/O fields may be unavailable for non-root users.

## Options

| Flag | Description |
| --- | --- |
| `--limit N` | Maximum rows shown in terminal views |
| `--sort cpu\|mem\|pid\|command\|time\|io\|threads` | Sort field |
| `--interval SECONDS` | Watch interval |
| `--count N` | Watch iterations; 0 means unlimited |
| `--watch [SECONDS]` | Legacy watch alias |
| `--threads` | Include individual threads |
| `--zombie` | Include zombie processes |
| `--vm-size` | Display virtual memory instead of RSS in top view |
| `--depth N` | Maximum process-tree depth |
| `--thread-limit N` | Maximum extra thread rows per process |
| `--max-scan N` | Maximum process directories scanned |
| `--cmd-length N` | Command-line display length |
| `--palette NAME` | ANSI color palette |
| `--color auto\|always\|never` | Terminal color behavior |
| `--format table\|json\|jsonl\|csv` | Standard-output representation |
| `--output FILE` | Snapshot or timeline destination |
| `--baseline FILE` | Saved JSON snapshot for diff |
| `--pid PID` | Target for inspect |
| `--no-io` | Skip process I/O reads |
| `--proc-root PATH` | Alternative procfs directory, useful for fixtures |
| `--version` | Display version |

`--kb` and `--mb` are retained as accepted legacy flags; the new table uses automatically scaled IEC units instead.

## Architecture

The single file separates concerns into lightweight functions and a `Collector` class:

1. **Acquisition:** bounded reads from procfs files and directory enumeration
2. **Parsing:** kernel stat fields, status fields, I/O counters, and command lines
3. **Identity:** PID/TID plus process start ticks, preventing PID reuse contamination
4. **Sampling:** monotonic clock for interval CPU measurements and I/O deltas
5. **Analysis:** sorting, state census, lifecycle events, and baseline differences
6. **Rendering:** tables, hierarchical trees, summary reports, and truecolor topology
7. **Serialization:** JSON, JSONL, CSV, and atomic JSON snapshot writes

### Kernel field details

The `/proc/[pid]/stat` parser locates the final closing parenthesis before splitting the remaining fields, because `comm` can contain spaces or parentheses. With `state` at remaining-field index 0, `utime` is index 11, `stime` index 12, and `starttime` index 19. The clock-tick frequency comes from `os.sysconf('SC_CLK_TCK')` and page size from `os.sysconf('SC_PAGE_SIZE')`.

### Operational limits

This is a userspace sampling tool, not an event-perfect kernel tracer. Very short-lived processes can appear and disappear between samples. Procfs reads are not atomic across files. Snapshot comparison shows observed differences, not a guaranteed complete history. The tree view limits output count and depth; large process hierarchies may require higher limits. Topology bars are proportional to the largest value among the displayed rows.

The utility intentionally does **not** impose a cumulative CPU-time resource limit on itself, allowing long-running watch sessions. Ctrl+C or SIGTERM stops watch mode cleanly.

## Verification

```bash
python3 -m py_compile main.py
python3 main.py top --limit 5 --color never
python3 main.py summary --limit 5
python3 main.py topology --limit 5 --color never
python3 main.py watch --count 2 --interval 0.2 --color never
python3 main.py baseline --output /tmp/procstat-before.json
python3 main.py diff --baseline /tmp/procstat-before.json --limit 5
```

## License

Copyright (C) 2026 procstat-python contributors

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See `LICENSE` for the full text.

## Version 2.1.0: Expanded terminal visualization

Version 2.1 adds a more expressive visual interface while preserving the original process monitoring and forensic workflows. The default palette is now **aurora**.

### New views

| Command | Description |
| --- | --- |
| `dashboard` | Colorful system overview with memory and CPU gauges, load averages, process-state distribution, resource leaders, and lifecycle counts |
| `heatmap` | Per-process CPU and resident-memory density fields rendered with Unicode blocks and truecolor gradients |
| `pressure` | Kernel CPU, memory, and I/O pressure stall information from `/proc/pressure`, when available |
| `io` | Process I/O totals and per-sample read/write deltas |
| `states` | Color-coded Linux scheduler-state distribution with proportional bars |

### Color palettes

`aurora`, `solar`, `ice`, `ocean`, `ember`, `violet`, `forest`, and `mono`.

Colors automatically activate when output is a terminal, unless `NO_COLOR` is set. Use `--color always` to force ANSI truecolor or `--color never` for plain output. The `--palette` flag controls the gradient used for charts, gauges, and headers. Process states have their own semantic colors: running green, sleeping blue, disk sleep amber, zombies red, stopped violet, and idle gray.

### Examples

```bash
python3 main.py dashboard --palette aurora
python3 main.py dashboard --palette solar --color always
python3 main.py heatmap --sort cpu --limit 35 --palette violet
python3 main.py heatmap --sort mem --limit 25 --palette ice
python3 main.py pressure --palette ember
python3 main.py states --palette forest
python3 main.py io --limit 30
python3 main.py topology --palette aurora --limit 40
python3 main.py watch --view dashboard --interval 1 --count 20
python3 main.py watch --view heatmap --interval 2 --count 10
python3 main.py watch --view io --interval 1 --count 10
python3 main.py watch --view states --interval 2
```

`watch` uses `dashboard` as its default view. Use `--view` to select `top`, `dashboard`, `heatmap`, `topology`, `pressure`, `io`, `states`, or `summary`. The dashboard shows a CPU-history sparkline when running in watch mode. For machine-readable monitoring, select `--format jsonl` or export samples to JSONL or CSV as documented above.

### System telemetry

The expanded collector reads `/proc/meminfo`, `/proc/loadavg`, and `/proc/pressure/{cpu,memory,io}` in addition to the process files used by earlier versions. Missing PSI data is reported as unavailable rather than fabricated. The memory gauge approximates memory used as `MemTotal - MemAvailable`, and should not be interpreted as a sum of process RSS values. The CPU gauge uses summed process CPU activity; first-sample readings are lifetime averages and later readings are interval deltas. PSI `avg10`, `avg60`, and `avg300` describe the percentage of time tasks were stalled over those windows, not CPU utilization.

The first sample's I/O deltas are zero because there is no previous observation. Subsequent watch samples use differences in kernel counters. Process I/O data can be limited by permissions and kernel configuration. Process RSS values can count shared physical pages more than once across processes.

### Validation

The Python file has been syntax-checked and exercised on Linux with dashboard, heatmap, tree, pressure, I/O, watch, snapshot, and diff commands. PSI files were unavailable in the test environment, so the PSI parsing branch was not validated against live PSI metrics there. Users should verify the interface and telemetry on their own Linux hosts.

## Version 3.0.0: The Quiet Observatory

The 3.0 release extends the project beyond one thousand lines of Python and adds a deliberately warm, restrained visual language. Its new views favor muted copper, amber, lavender, moss, cocoa, and twilight shades instead of aggressively saturated monitoring displays. The ANSI rendering is optional and respects `NO_COLOR` and terminal detection.

### Cozy palettes

The additional palettes are `hearth`, `lantern`, `dusk`, `cocoa`, `moss`, and `rosewood`. `hearth` is now the default. The original `aurora`, `ocean`, `ember`, `violet`, `forest`, `solar`, `ice`, and `mono` remain available.

```bash
python3 main.py hearth --palette hearth
python3 main.py hearth --palette dusk --color always
python3 main.py lanterns --palette lantern --sort cpu --limit 30
python3 main.py garden --palette moss --sort mem --limit 30
```

### New observatory views

| Command | Description |
| --- | --- |
| `hearth` | Multi-section system dashboard with memory, CPU, scheduler states, lifecycle and resource leaders |
| `lanterns` | Warm, per-process CPU luminance with process identity and resident memory |
| `garden` | Vertical activity stems and horizontal relative RSS fields |
| `moonlight` | Percentile summaries and logarithmic distribution histograms |
| `breathing` | Soft PSI panels for CPU, memory and I/O stall signals |
| `river` | Read/write I/O delta flows for individual processes |
| `weave` | Thread-count distribution across processes |
| `census` | Process counts, percentiles, states and resource totals |
| `identities` | New and exited process IDs and PID reuse events |
| `signals` | Non-diagnostic heuristic observations of memory and scheduler conditions |
| `report` | Multi-view printable observatory report |

The original commands `top`, `tree`, `summary`, `topology`, `dashboard`, `heatmap`, `pressure`, `io`, `states`, `watch`, `snapshot`, `baseline`, `diff`, and `inspect` are retained.

### Cozy watch sessions

```bash
python3 main.py watch --view hearth --palette hearth --interval 2
python3 main.py watch --view lanterns --palette lantern --interval 1 --count 10
python3 main.py watch --view breathing --palette dusk --interval 3
python3 main.py watch --view river --palette cocoa --interval 2
```

The first sample of a collector has no earlier I/O baseline. Process lifecycle changes and I/O deltas become meaningful after subsequent scans. Watch mode avoids clearing noninteractive output, making it suitable for log capture.

### Artwork and portable reports

Export an SVG process atlas and a Markdown observation report from a single scan:

```bash
python3 main.py hearth --palette rosewood --svg process-atlas.svg --markdown observation.md
```

The SVG is self-contained and uses a dark background with two soft-colored resource bars per process. Names are HTML-escaped. The Markdown report includes a process census, top CPU consumers, scheduler-state counts, and heuristic observations. These files can be generated alongside JSON/CSV snapshots:

```bash
python3 main.py hearth --output snapshot.json --svg atlas.svg --markdown report.md
```

### Statistics and interpretation

`moonlight` computes interpolated median, P90 and P99 values for CPU utilization, RSS, thread count, and context-switch deltas. Memory and thread histograms use logarithmic bucket spacing to make heavily skewed distributions more legible. CPU percentages are expressed relative to a single logical CPU, so multithreaded processes can exceed 100 percent. RSS totals are sums of process RSS values, not unique physical memory usage; shared pages may be counted multiple times.

`signals` contains only simple heuristics. Its messages are observations rather than root-cause diagnoses. In particular, high resident memory, sleeping processes and PSI stall values need to be interpreted in context.

### Validation commands

```bash
python3 -m py_compile main.py
python3 main.py --help
python3 main.py hearth --color never
python3 main.py moonlight --color never
python3 main.py watch --view lanterns --count 2 --interval 0.2 --color never
python3 main.py hearth --svg atlas.svg --markdown report.md
```

The tool requires Linux and Python 3.10 or newer. No packages outside the Python standard library are needed. GPLv3 licensing remains unchanged.
