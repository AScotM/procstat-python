#!/usr/bin/env python3

import os
import sys
import time
import signal
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import resource

DEFAULT_HERTZ = 100.0
MIN_UPTIME = 0.1
DEFAULT_LIMIT = 20
DEFAULT_INTERVAL = 2
DEFAULT_MAX_PID_SCAN = 131072
DEFAULT_THREAD_LIMIT = 1000
DEFAULT_CMD_LENGTH = 80
FLOAT_EPSILON = 0.00001
VALID_SORTS = ['cpu', 'mem', 'pid', 'command', 'time']

class ProcessInfo:
    def __init__(self, pid: int, ppid: int, cpu: float, memory: float, 
                 command: str, state: str, ptime: float, ptype: str = 'process'):
        self.pid = pid
        self.ppid = ppid
        self.cpu = cpu
        self.memory = memory
        self.command = command
        self.state = state
        self.time = ptime
        self.ptype = ptype

class ProcStat:
    def __init__(self):
        if not sys.platform.startswith('linux'):
            sys.stderr.write("Error: This tool only works on Linux systems.\n")
            sys.exit(1)
        
        self.parse_arguments()
        self.check_privileges()
        self.validate_proc_filesystem()
        self.hertz = self.detect_hertz()
        self.validate_options()
        self.setup_resource_limits()
        
        self.shutdown_requested = False
        self.previous_stats: Dict[str, Dict[str, float]] = {}
        self.previous_uptime: Optional[float] = None
        self.last_scan_time = 0.0
        self.initial_scan_complete = False
    
    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description='Process Monitor - Linux Process Statistics',
            add_help=True
        )
        
        parser.add_argument('--limit', type=int, default=DEFAULT_LIMIT, help='Show top N processes')
        parser.add_argument('--sort', type=str, default='cpu', help='Sort by: cpu, mem, pid, command, time')
        parser.add_argument('--watch', nargs='?', const=DEFAULT_INTERVAL, type=int, help='Refresh every N seconds')
        parser.add_argument('--verbose', action='store_true', help='Show debug information')
        parser.add_argument('--zombie', action='store_true', help='Include zombie processes')
        parser.add_argument('--threads', action='store_true', help='Show thread information')
        parser.add_argument('--thread-limit', type=int, default=DEFAULT_THREAD_LIMIT, help='Maximum threads per process')
        parser.add_argument('--max-scan', type=int, default=DEFAULT_MAX_PID_SCAN, help='Maximum PIDs to scan')
        parser.add_argument('--kb', action='store_true', help='Show memory in kilobytes')
        parser.add_argument('--mb', action='store_true', help='Show memory in megabytes (default)')
        parser.add_argument('--vm-size', action='store_true', help='Use VmSize instead of VmRSS for memory')
        
        try:
            args = parser.parse_args()
        except SystemExit:
            sys.exit(0)
        
        self.limit = args.limit
        self.sort = args.sort
        self.watch = args.watch is not None
        self.interval = args.watch if args.watch is not None else DEFAULT_INTERVAL
        self.verbose = args.verbose
        self.zombie = args.zombie
        self.threads = args.threads
        self.thread_limit = args.thread_limit
        self.max_pid_scan = args.max_scan
        self.use_vm_size = args.vm_size
        
        if args.mb:
            self.use_mb = True
        elif args.kb:
            self.use_mb = False
        else:
            self.use_mb = True
    
    def check_privileges(self):
        if os.geteuid() != 0:
            sys.stderr.write("Warning: Running without root privileges. Some processes may not be visible.\n")
    
    def validate_options(self):
        if self.sort not in VALID_SORTS:
            sys.stderr.write(f"Warning: Invalid sort option '{self.sort}'. Using 'cpu'.\n")
            self.sort = 'cpu'
        
        if self.limit < 1 or self.limit > 1000:
            sys.stderr.write("Warning: Limit must be between 1 and 1000. Using default.\n")
            self.limit = DEFAULT_LIMIT
        
        if self.interval < 1 or self.interval > 3600:
            sys.stderr.write("Warning: Interval must be between 1 and 3600. Using default.\n")
            self.interval = DEFAULT_INTERVAL
        
        if self.thread_limit < 1 or self.thread_limit > 10000:
            sys.stderr.write("Warning: Thread limit must be between 1 and 10000. Using default.\n")
            self.thread_limit = DEFAULT_THREAD_LIMIT
        
        if self.max_pid_scan < 100 or self.max_pid_scan > 1000000:
            sys.stderr.write("Warning: Max scan must be between 100 and 1000000. Using default.\n")
            self.max_pid_scan = DEFAULT_MAX_PID_SCAN
    
    def setup_resource_limits(self):
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            max_files = min(self.max_pid_scan * 3, hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (max_files, hard))
        except (ValueError, resource.error) as e:
            if self.verbose:
                sys.stderr.write(f"Debug: Could not set file limit: {e}\n")
        
        try:
            max_time = 30
            resource.setrlimit(resource.RLIMIT_CPU, (max_time, max_time))
        except (ValueError, resource.error) as e:
            if self.verbose:
                sys.stderr.write(f"Debug: Could not set CPU limit: {e}\n")
    
    def validate_proc_filesystem(self):
        if not os.path.exists('/proc') or not os.path.isdir('/proc'):
            raise RuntimeError('/proc filesystem not available or not mounted')
        
        if not (os.path.exists('/proc/self') or os.path.exists('/proc/version')):
            raise RuntimeError('/proc does not appear to be a valid proc filesystem')
        
        if not os.access('/proc/uptime', os.R_OK):
            raise RuntimeError('/proc/uptime is not readable. Check permissions or run with sudo')
    
    def get_uptime(self) -> float:
        try:
            with open('/proc/uptime', 'r') as f:
                content = f.read().strip()
            
            parts = content.split()
            if len(parts) < 2:
                raise RuntimeError('Invalid format in /proc/uptime')
            
            uptime = float(parts[0])
            if uptime <= FLOAT_EPSILON:
                raise RuntimeError('Invalid uptime value in /proc/uptime')
            
            return uptime
        except (IOError, ValueError) as e:
            raise RuntimeError(f'Cannot read /proc/uptime: {e}')
    
    def format_uptime(self, uptime: float) -> str:
        days = int(uptime // 86400)
        hours = int((uptime % 86400) // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def detect_hertz(self) -> float:
        try:
            with open('/proc/self/stat', 'r') as f:
                content = f.read()
            
            fields = content.split()
            if len(fields) > 41:
                clock_ticks = int(fields[41])
                if clock_ticks > 0:
                    if self.verbose:
                        sys.stderr.write(f"Debug: Detected HERTZ from /proc/self/stat: {clock_ticks}\n")
                    return float(clock_ticks)
        except (IOError, ValueError, IndexError):
            pass
        
        try:
            result = subprocess.run(['getconf', 'CLK_TCK'], 
                                   capture_output=True, text=True, check=False)
            if result.returncode == 0:
                hz = int(result.stdout.strip())
                if hz > 0:
                    if self.verbose:
                        sys.stderr.write(f"Debug: Detected HERTZ from getconf: {hz}\n")
                    return float(hz)
        except (subprocess.SubprocessError, ValueError):
            pass
        
        if self.verbose:
            sys.stderr.write(f"Debug: Using default HERTZ value: {DEFAULT_HERTZ}\n")
        return DEFAULT_HERTZ
    
    def run(self):
        if self.watch:
            self.run_watch_mode()
        else:
            self.run_once()
    
    def run_watch_mode(self):
        self.setup_signal_handlers()
        
        print(f"Process Monitor - Refresh every {self.interval}s (Ctrl+C to stop)")
        
        iteration = 0
        while not self.shutdown_requested:
            if iteration > 0:
                print("\033[2J\033[;H", end='')
            
            try:
                uptime = self.get_uptime()
                self.display_header(iteration, uptime)
                self.run_once_with_uptime(uptime)
            except RuntimeError as e:
                print(f"Error: {e}")
                self.shutdown_requested = True
                break
            
            iteration += 1
            self.sleep_with_interrupt(self.interval)
        
        print("\nShutting down...")
    
    def setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self.handle_signal)
    
    def handle_signal(self, signum, frame):
        self.shutdown_requested = True
    
    def sleep_with_interrupt(self, seconds: int):
        remaining = seconds
        while remaining > 0 and not self.shutdown_requested:
            sleep_time = min(remaining, 1)
            time.sleep(sleep_time)
            remaining -= sleep_time
    
    def display_header(self, iteration: int, uptime: float):
        memory_unit = "MB" if self.use_mb else "KB"
        memory_type = "VmSize" if self.use_vm_size else "VmRSS"
        uptime_str = self.format_uptime(uptime)
        
        print(f"Process Monitor - Iteration #{iteration} - {time.strftime('%Y-%m-%d %H:%M:%S')} - Uptime: {uptime_str}")
        
        modes = []
        if self.zombie:
            modes.append('Zombies')
        if self.threads:
            modes.append('Threads')
        if self.use_vm_size:
            modes.append('VmSize')
        
        mode_str = f" | Modes: {', '.join(modes)}" if modes else ""
        
        print(f"Sorting by: {self.sort.upper()} | Showing top: {self.limit} | Refresh: {self.interval}s | Memory: {memory_unit} ({memory_type}){mode_str}")
        print("=" * 80)
        print()
    
    def run_once(self):
        try:
            if self.watch:
                time.sleep(0.1)
            
            uptime = self.get_uptime()
            self.previous_uptime = uptime
            self.last_scan_time = time.time()
            self.run_once_with_uptime(uptime)
        except RuntimeError as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    def run_once_with_uptime(self, uptime: float):
        start_time = time.time()
        processes = []
        proc_count = 0
        error_count = 0
        
        pids = self.scan_proc_directory()
        if pids is None:
            print("Error: Cannot access /proc directory. Check permissions.")
            return
        
        current_scan_time = time.time()
        
        for pid in pids:
            proc_count += 1
            
            if proc_count > self.max_pid_scan:
                if self.verbose:
                    sys.stderr.write(f"Warning: Too many processes, stopping scan at {proc_count}\n")
                break
            
            process_info = self.read_process(pid, uptime)
            if process_info is not None:
                processes.append(process_info)
                
                if self.threads:
                    threads = self.read_threads(pid, uptime)
                    processes.extend(threads)
            else:
                error_count += 1
        
        if not self.initial_scan_complete:
            self.initial_scan_complete = True
        
        execution_time = (time.time() - start_time) * 1000
        
        if self.verbose and not self.watch:
            sys.stderr.write(f"Debug: Scanned {proc_count} processes, {error_count} errors, took {execution_time:.2f}ms\n")
        
        self.render(processes)
        
        if not self.watch:
            print(f"\nTotal processes displayed: {len(processes)}")
            if error_count > 0:
                print(f"Note: {error_count} processes could not be read (permissions or terminated)")
        
        self.previous_uptime = uptime
        self.last_scan_time = current_scan_time
    
    def scan_proc_directory(self) -> Optional[List[int]]:
        try:
            pids = []
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    pids.append(int(entry))
            return pids
        except (OSError, PermissionError):
            return None
    
    def read_process(self, pid: int, uptime: float) -> Optional[ProcessInfo]:
        stat_path = f"/proc/{pid}/stat"
        try:
            with open(stat_path, 'r') as f:
                content = f.read().strip()
        except (IOError, PermissionError):
            return None
        
        if not self.zombie and ') Z ' in content:
            return None
        
        last_paren = content.rfind(')')
        if last_paren == -1:
            return None
        
        name = content[:last_paren].strip('()')
        data = content[last_paren + 2:]
        fields = data.split()
        
        if len(fields) < 22:
            return None
        
        try:
            state = fields[0]
            ppid = int(fields[1])
            utime = float(fields[11])
            stime = float(fields[12])
            cutime = float(fields[13])
            cstime = float(fields[14])
            start_time = float(fields[21])
        except (IndexError, ValueError):
            return None
        
        total_time = utime + stime + cutime + cstime
        current_time = time.time()
        
        previous_key = f"{pid}_process"
        previous_stat = self.previous_stats.get(previous_key)
        
        cpu_usage = 0.0
        
        if previous_stat and self.initial_scan_complete:
            previous_total_time = previous_stat['total_time']
            previous_timestamp = previous_stat['timestamp']
            actual_interval = current_time - previous_timestamp
            
            if actual_interval > MIN_UPTIME:
                time_diff_seconds = (total_time - previous_total_time) / self.hertz
                cpu_usage = 100.0 * (time_diff_seconds / actual_interval)
                if cpu_usage < 0:
                    cpu_usage = 0.0
        elif not self.watch or not self.initial_scan_complete:
            process_start = start_time / self.hertz
            process_lifetime = uptime - process_start
            
            if process_lifetime > MIN_UPTIME:
                cpu_usage = 100.0 * (total_time / self.hertz) / process_lifetime
        
        self.previous_stats[previous_key] = {
            'total_time': total_time,
            'timestamp': current_time
        }
        
        memory = self.get_memory_usage(pid)
        command = self.get_process_command(pid, name)
        
        return ProcessInfo(
            pid=pid,
            ppid=ppid,
            cpu=round(cpu_usage, 1),
            memory=round(memory, 1),
            command=command,
            state=state,
            ptime=round(total_time / self.hertz, 1),
            ptype='process'
        )
    
    def read_threads(self, pid: int, uptime: float) -> List[ProcessInfo]:
        threads = []
        task_dir = Path(f"/proc/{pid}/task")
        
        if not task_dir.is_dir():
            return threads
        
        count = 0
        try:
            for entry in task_dir.iterdir():
                if count >= self.thread_limit:
                    break
                
                try:
                    tid = int(entry.name)
                except ValueError:
                    continue
                
                if tid == pid:
                    continue
                
                thread = self.read_thread(pid, tid, uptime)
                if thread is not None:
                    threads.append(thread)
                    count += 1
        except (OSError, PermissionError):
            pass
        
        return threads
    
    def read_thread(self, pid: int, tid: int, uptime: float) -> Optional[ProcessInfo]:
        stat_path = f"/proc/{pid}/task/{tid}/stat"
        try:
            with open(stat_path, 'r') as f:
                content = f.read().strip()
        except (IOError, PermissionError):
            return None
        
        last_paren = content.rfind(')')
        if last_paren == -1:
            return None
        
        name = content[:last_paren].strip('()')
        data = content[last_paren + 2:]
        fields = data.split()
        
        if len(fields) < 22:
            return None
        
        try:
            state = fields[0]
            utime = float(fields[11])
            stime = float(fields[12])
            start_time = float(fields[21])
        except (IndexError, ValueError):
            return None
        
        total_time = utime + stime
        current_time = time.time()
        
        previous_key = f"{pid}_{tid}_thread"
        previous_stat = self.previous_stats.get(previous_key)
        
        cpu_usage = 0.0
        
        if previous_stat and self.initial_scan_complete:
            previous_total_time = previous_stat['total_time']
            previous_timestamp = previous_stat['timestamp']
            actual_interval = current_time - previous_timestamp
            
            if actual_interval > MIN_UPTIME:
                time_diff_seconds = (total_time - previous_total_time) / self.hertz
                cpu_usage = 100.0 * (time_diff_seconds / actual_interval)
                if cpu_usage < 0:
                    cpu_usage = 0.0
        elif not self.watch or not self.initial_scan_complete:
            process_start = start_time / self.hertz
            process_lifetime = uptime - process_start
            
            if process_lifetime > MIN_UPTIME:
                cpu_usage = 100.0 * (total_time / self.hertz) / process_lifetime
        
        self.previous_stats[previous_key] = {
            'total_time': total_time,
            'timestamp': current_time
        }
        
        memory = self.get_memory_usage(tid)
        
        return ProcessInfo(
            pid=tid,
            ppid=pid,
            cpu=round(cpu_usage, 1),
            memory=round(memory, 1),
            command=f"└─ {self.sanitize_output(name)}",
            state=state,
            ptime=round(total_time / self.hertz, 1),
            ptype='thread'
        )
    
    def get_memory_usage(self, pid: int) -> float:
        status_path = f"/proc/{pid}/status"
        try:
            with open(status_path, 'r') as f:
                for line in f:
                    if self.use_vm_size and line.startswith('VmSize:'):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                mem = int(parts[1])
                                if self.use_mb:
                                    return mem / 1024.0
                                return float(mem)
                            except ValueError:
                                pass
                    elif not self.use_vm_size and line.startswith('VmRSS:'):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                rss = int(parts[1])
                                if self.use_mb:
                                    return rss / 1024.0
                                return float(rss)
                            except ValueError:
                                return 0.0
        except (IOError, PermissionError):
            pass
        
        return 0.0
    
    def get_process_command(self, pid: int, default_name: str) -> str:
        cmdline_path = f"/proc/{pid}/cmdline"
        try:
            with open(cmdline_path, 'rb') as f:
                content = f.read()
            
            if not content:
                return f"[{self.sanitize_output(default_name)}]"
            
            parts = content.split(b'\x00')
            cmd_parts = []
            for part in parts:
                if part:
                    try:
                        cmd_parts.append(part.decode('utf-8', errors='replace'))
                    except UnicodeDecodeError:
                        cmd_parts.append(part.decode('latin-1', errors='replace'))
            
            cmdline = ' '.join(cmd_parts).strip()
            if not cmdline:
                return f"[{self.sanitize_output(default_name)}]"
            
            cmdline = self.sanitize_output(cmdline)
            return self.truncate_string(cmdline, DEFAULT_CMD_LENGTH)
        except (IOError, PermissionError):
            return f"[{self.sanitize_output(default_name)}]"
    
    def sanitize_output(self, text: str) -> str:
        result = []
        for c in text:
            if 32 <= ord(c) < 127 or c in '\t\n\r':
                result.append(c)
            else:
                result.append('?')
        return ''.join(result).strip()
    
    def truncate_string(self, text: str, max_length: int) -> str:
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + '...'
    
    def render(self, processes: List[ProcessInfo]):
        if not processes:
            print("No processes found or insufficient permissions.")
            if os.geteuid() != 0:
                print("Try running with sudo for more complete results.")
            return
        
        if self.sort == 'cpu':
            processes.sort(key=lambda x: (-x.cpu, x.pid))
        elif self.sort == 'mem':
            processes.sort(key=lambda x: (-x.memory, x.pid))
        elif self.sort == 'pid':
            processes.sort(key=lambda x: x.pid)
        elif self.sort == 'command':
            processes.sort(key=lambda x: (x.command.lower(), x.pid))
        elif self.sort == 'time':
            processes.sort(key=lambda x: (-x.time, x.pid))
        
        display_count = min(self.limit, len(processes))
        display_processes = processes[:display_count]
        
        memory_unit = "MB" if self.use_mb else "KB"
        memory_type = "VMSIZE" if self.use_vm_size else "MEM"
        memory_label = f"{memory_type}({memory_unit})"
        
        print(f"{'PID':<6} {'CPU%':<6} {memory_label:<12} {'STATE':<6} {'COMMAND'}")
        print("-" * 80)
        
        total_cpu = 0.0
        total_mem = 0.0
        
        for proc in display_processes:
            pid_display = f"  {proc.pid}" if proc.ptype == 'thread' else str(proc.pid)
            
            print(f"{pid_display:<6} {proc.cpu:<6.1f} {proc.memory:<12.1f} {proc.state:<6} {proc.command}")
            
            total_cpu += proc.cpu
            total_mem += proc.memory
        
        if not self.watch:
            print("-" * 80)
            print(f"Top {display_count} processes: {total_cpu:.1f}% CPU, {total_mem:.1f} {memory_unit}")

def main():
    try:
        proc_stat = ProcStat()
        proc_stat.run()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
    except RuntimeError as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.stderr.write("Use --help for usage information.\n")
        sys.stderr.write("Note: Some systems may require sudo/root privileges.\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Unexpected error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
