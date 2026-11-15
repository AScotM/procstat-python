#!/usr/bin/env python3
import argparse
import collections
import csv
import datetime
import json
import math
import os
import pathlib
import re
import signal
import sys
import time

VERSION = '3.0.0'
STATES = {'R':'running','S':'sleeping','D':'disk-sleep','Z':'zombie','T':'stopped','t':'tracing','X':'dead','I':'idle','P':'parked'}
PALETTES = {'ocean':((49,208,226),(80,126,245)), 'ember':((255,194,83),(240,78,101)), 'violet':((185,130,255),(75,210,240)), 'forest':((95,220,150),(60,145,180)), 'aurora':((42,235,183),(189,100,255)), 'solar':((255,210,74),(255,75,111)), 'ice':((120,220,255),(82,110,250)), 'mono':((210,210,210),(100,100,100)), 'hearth':((255,191,145),(173,121,161)), 'lantern':((255,208,130),(145,170,147)), 'dusk':((209,165,197),(110,148,178)), 'cocoa':((214,176,146),(154,129,122)), 'moss':((178,201,146),(120,151,143)), 'rosewood':((239,161,158),(162,126,162))}

def read_text(path, limit=1048576):
    try:
        with open(path,'rb') as f:
            return f.read(limit).decode('utf-8','replace')
    except (OSError,ValueError):
        return None

def read_bytes(path, limit=1048576):
    try:
        with open(path,'rb') as f:
            return f.read(limit)
    except (OSError,ValueError):
        return None

def safe(s):
    return ''.join(c if c.isprintable() and c not in '\x1b\x7f' else '?' for c in str(s))

def stat_parse(raw):
    if not raw:
        return None
    left=raw.find('('); right=raw.rfind(')')
    if left<0 or right<=left:
        return None
    try:
        pid=int(raw[:left].strip()); comm=raw[left+1:right]; fields=raw[right+1:].split()
        if len(fields)<22:
            return None
        return {'pid':pid,'comm':comm,'state':fields[0],'ppid':int(fields[1]),'utime':int(fields[11]),'stime':int(fields[12]),'cutime':int(fields[13]),'cstime':int(fields[14]),'priority':int(fields[15]),'nice':int(fields[16]),'threads':int(fields[17]),'start_ticks':int(fields[19]),'vsize':int(fields[20]),'rss_pages':int(fields[21]),'processor':int(fields[36]) if len(fields)>36 else None}
    except (ValueError,IndexError):
        return None

def kv_status(raw):
    result={}
    if raw:
        for line in raw.splitlines():
            if ':' in line:
                k,v=line.split(':',1); result[k]=v.strip()
    return result

def kb_field(status, key):
    try:
        return int(status.get(key,'0').split()[0])*1024
    except (ValueError,IndexError):
        return 0

def io_fields(raw):
    out={}
    if raw:
        for line in raw.splitlines():
            if ':' in line:
                k,v=line.split(':',1)
                try: out[k.strip()]=int(v.strip())
                except ValueError: pass
    return out

def uptime_at(root):
    raw=read_text(os.path.join(root,'uptime'))
    try: return float(raw.split()[0])
    except (ValueError,IndexError,AttributeError): return None

def cpu_count(root):
    raw=read_text(os.path.join(root,'stat')) or ''
    n=sum(bool(re.match(r'^cpu\d+\s',line)) for line in raw.splitlines())
    return n or os.cpu_count() or 1

def iso_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')

def clamp(x,low,high):
    return max(low,min(high,x))

def size_fmt(value):
    v=float(value)
    for unit in ('B','KiB','MiB','GiB','TiB'):
        if abs(v)<1024 or unit=='TiB': return f'{v:.1f}{unit}'
        v/=1024

def tint(text, rgb, enabled):
    if not enabled: return str(text)
    r,g,b=rgb
    return f'\033[38;2;{r};{g};{b}m{text}\033[0m'

def gradient(frac,palette):
    a,b=PALETTES[palette]; f=clamp(frac,0,1)
    return tuple(round(x+(y-x)*f) for x,y in zip(a,b))

def bar(value,maximum,width,palette,color):
    n=round(width*clamp(value/max(maximum,0.0001),0,1))
    if not color: return '#' * n + '-'*(width-n)
    return ''.join(tint('█',gradient(i/max(width-1,1),palette),True) for i in range(n))+'░'*(width-n)

class Collector:
    def __init__(self,root='/proc',threads=False,include_zombies=False,vm_size=False,max_scan=131072,thread_limit=1000,cmd_length=120,io=True):
        self.root=root; self.threads=threads; self.include_zombies=include_zombies
        self.vm_size=vm_size; self.max_scan=max_scan; self.thread_limit=thread_limit
        self.cmd_length=cmd_length; self.io=io
        self.hz=os.sysconf('SC_CLK_TCK'); self.page=os.sysconf('SC_PAGE_SIZE')
        self.cores=cpu_count(root)
        self.prev={}; self.last_mono=None; self.previous_pids={}; self.generation=0

    def process(self,pid,tid=None):
        base=os.path.join(self.root,str(pid))
        if tid is not None: base=os.path.join(base,'task',str(tid))
        stat=stat_parse(read_text(os.path.join(base,'stat')))
        if not stat or (stat['state']=='Z' and not self.include_zombies): return None
        status=kv_status(read_text(os.path.join(base,'status')))
        if tid is None:
            cmd=read_bytes(os.path.join(base,'cmdline'))
            name=safe(' '.join(x.decode('utf-8','replace') for x in cmd.split(b'\0') if x)) if cmd else '['+safe(stat['comm'])+']'
            name=name[:self.cmd_length]
        else:
            name='['+safe(stat['comm'])+']'
        rss=kb_field(status,'VmRSS') or stat['rss_pages']*self.page
        vsize=kb_field(status,'VmSize') or stat['vsize']
        io=io_fields(read_text(os.path.join(base,'io'))) if self.io else {}
        ctx_vol=int(status.get('voluntary_ctxt_switches','0') or 0)
        ctx_invol=int(status.get('nonvoluntary_ctxt_switches','0') or 0)
        key=(pid,tid or pid,stat['start_ticks'])
        total=stat['utime']+stat['stime']
        old=self.prev.get(key)
        cpu=0.0
        if old and self.last_mono is not None:
            elapsed=self._elapsed
            cpu=max(0.0,100*(total-old['ticks'])/self.hz/elapsed) if elapsed>0 else 0.0
        elif self._uptime is not None:
            lifetime=self._uptime-stat['start_ticks']/self.hz
            cpu=max(0.0,100*total/self.hz/lifetime) if lifetime>0.1 else 0.0
        self._current[key]={'ticks':total,'io':io,'ctx':ctx_vol+ctx_invol}
        delta_io={k:max(0,v-old['io'].get(k,0)) for k,v in io.items()} if old else {}
        return {'pid':stat['pid'],'tgid':pid,'ppid':stat['ppid'] if tid is None else pid,'type':'thread' if tid is not None else 'process',
                'name':name,'comm':safe(stat['comm']),'state':stat['state'],'cpu':round(cpu,2),'cpu_seconds':round(total/self.hz,3),
                'rss':rss,'vsize':vsize,'memory':vsize if self.vm_size else rss,'threads':stat['threads'],
                'priority':stat['priority'],'nice':stat['nice'],'processor':stat['processor'],'start_ticks':stat['start_ticks'],
                'identity':f"{pid}:{tid or pid}:{stat['start_ticks']}",'io':io,'io_delta':delta_io,
                'ctx_voluntary':ctx_vol,'ctx_involuntary':ctx_invol,'ctx_delta':max(0,ctx_vol+ctx_invol-old['ctx']) if old else 0}

    def scan(self):
        start=time.monotonic(); self._uptime=uptime_at(self.root)
        self._elapsed=max(0.00001,start-self.last_mono) if self.last_mono is not None else 0
        self._current={}; errors=0; records=[]
        try:
            pids=sorted(int(x) for x in os.listdir(self.root) if x.isdigit())[:self.max_scan]
        except OSError as e: raise RuntimeError(f'cannot scan {self.root}: {e}') from e
        for pid in pids:
            p=self.process(pid)
            if p is None: errors+=1; continue
            records.append(p)
            if self.threads:
                try:
                    tids=sorted(int(x) for x in os.listdir(os.path.join(self.root,str(pid),'task')) if x.isdigit() and int(x)!=pid)
                except OSError: tids=[]
                for tid in tids[:self.thread_limit]:
                    t=self.process(pid,tid)
                    if t is not None: records.append(t)
        identities={p['pid']:p['start_ticks'] for p in records if p['type']=='process'}
        births=[pid for pid,start_tick in identities.items() if self.previous_pids.get(pid)!=start_tick]
        exits=[pid for pid in self.previous_pids if pid not in identities]
        reused=[pid for pid,start_tick in identities.items() if pid in self.previous_pids and self.previous_pids[pid]!=start_tick]
        self.previous_pids=identities; self.prev=self._current; self.last_mono=start; self.generation+=1
        processes=[p for p in records if p['type']=='process']
        return {'schema':'procstat-python/v2','timestamp':iso_now(),'generation':self.generation,'uptime':self._uptime,
                'cores':self.cores,'clock_ticks':self.hz,'scan_seconds':round(time.monotonic()-start,4),'errors':errors,
                'count':len(processes),'thread_rows':len(records)-len(processes),'births':births,'exits':exits,'pid_reuse':reused,
                'total_rss':sum(p['rss'] for p in processes),'total_cpu':round(sum(p['cpu'] for p in processes),2),'records':records,'system':read_system(self.root)}

def ordered(records,sort,limit):
    keys={'cpu':lambda p:(-p['cpu'],p['pid']),'mem':lambda p:(-p['memory'],p['pid']),
          'pid':lambda p:(p['pid'],p['type']),'command':lambda p:(p['name'].lower(),p['pid']),
          'time':lambda p:(-p['cpu_seconds'],p['pid']),'io':lambda p:(-p['io_delta'].get('read_bytes',0)-p['io_delta'].get('write_bytes',0),p['pid']),
          'threads':lambda p:(-p['threads'],p['pid'])}
    return sorted(records,key=keys[sort])[:limit] if limit else sorted(records,key=keys[sort])

def colored(args):
    return args.color=='always' or (args.color=='auto' and sys.stdout.isatty() and not os.environ.get('NO_COLOR'))

def paint(value,args,frac=0.0,bold=False):
    value=str(value)
    if not colored(args):
        return value
    r,g,b=gradient(frac,args.palette)
    return f"\033[{1 if bold else 22};38;2;{r};{g};{b}m{value}\033[0m"

def state_color(state):
    return {'R':(74,234,150),'S':(105,175,250),'D':(255,170,72),'Z':(255,78,108),'T':(205,140,255),'I':(140,155,174)}.get(state,(185,195,210))

def state_text(state,args):
    return tint(state,state_color(state),colored(args))

def separator(args,width=100):
    return paint('─'*width,args,0.35)

def headline(title,snapshot,args):
    print(paint('╭'+'─'*78+'╮',args,0.4))
    print(paint('│ ',args,0.4)+paint(f'{title:<76}',args,0.1,True)+paint(' │',args,0.4))
    print(paint('╰'+'─'*78+'╯',args,0.4))
    print(paint(f"{snapshot['timestamp']}  PID {snapshot['count']}  CPU {snapshot['total_cpu']:.1f}%  RSS {size_fmt(snapshot['total_rss'])}  cores {snapshot['cores']}",args,0.65))

def sparkline(values,width=36):
    if not values:
        return ' ' * width
    vals=list(values)[-width:]
    peak=max(max(vals),0.0001)
    glyphs='▁▂▃▄▅▆▇█'
    return ''.join(glyphs[min(7,int(7*max(0,v)/peak))] for v in vals).rjust(width)

def read_pressure(root):
    result={}
    for kind in ('cpu','memory','io'):
        raw=read_text(os.path.join(root,'pressure',kind))
        if raw is None:
            continue
        result[kind]={}
        for line in raw.splitlines():
            parts=line.split()
            if not parts:
                continue
            result[kind][parts[0]]={}
            for item in parts[1:]:
                if '=' in item:
                    k,v=item.split('=',1)
                    try: result[kind][parts[0]][k]=float(v)
                    except ValueError: pass
    return result

def read_meminfo(root):
    data=kv_status(read_text(os.path.join(root,'meminfo')))
    return {k:kb_field(data,k) for k in ('MemTotal','MemAvailable','MemFree','Cached','SwapTotal','SwapFree','Slab','SReclaimable')}

def read_loadavg(root):
    raw=read_text(os.path.join(root,'loadavg'))
    try: return [float(x) for x in raw.split()[:3]]
    except (ValueError,AttributeError): return []

def read_system(root):
    return {'pressure':read_pressure(root),'memory':read_meminfo(root),'loadavg':read_loadavg(root)}

def dashboard(snapshot,args,history=None):
    headline('PROCESS OBSERVATORY  /  LIVE SYSTEM ATLAS',snapshot,args)
    system=snapshot.get('system',{})
    memory=system.get('memory',{})
    total=memory.get('MemTotal',0)
    available=memory.get('MemAvailable',0)
    used=max(0,total-available)
    print(paint('  MEMORY PRESSURE',args,0.1,True))
    print(f"  {bar(used,max(total,1),42,args.palette,colored(args))}  {size_fmt(used)} / {size_fmt(total)}")
    print(paint('  PROCESS CPU LOAD',args,0.1,True))
    cpu=snapshot['total_cpu']
    print(f"  {bar(cpu,max(100,snapshot['cores']*100),42,args.palette,colored(args))}  {cpu:.1f}% / {snapshot['cores']*100}%")
    load=system.get('loadavg',[])
    if load: print('  LOAD AVERAGE  '+' / '.join(f'{x:.2f}' for x in load))
    if history:
        print(paint('  CPU HISTORY',args,0.2,True))
        print('  '+paint(sparkline(history),args,0.7))
    print('  '+separator(args,78))
    states=collections.Counter(p['state'] for p in snapshot['records'] if p['type']=='process')
    print(paint('  SCHEDULER STATES',args,0.1,True))
    print('  '+'  '.join(f'{state_text(k,args)} {v}' for k,v in sorted(states.items())))
    print('  '+separator(args,78))
    print(paint('  RESOURCE LEADERS',args,0.1,True))
    for title,key in (('CPU','cpu'),('RSS','mem'),('DISK I/O','io')):
        print('  '+paint(f'{title:<10}',args,0.3,True))
        rows=ordered([p for p in snapshot['records'] if p['type']=='process'],key,4)
        mx=max([p['cpu'] if key=='cpu' else p['rss'] if key=='mem' else p['io_delta'].get('read_bytes',0)+p['io_delta'].get('write_bytes',0) for p in rows] or [1])
        for p in rows:
            val=p['cpu'] if key=='cpu' else p['rss'] if key=='mem' else p['io_delta'].get('read_bytes',0)+p['io_delta'].get('write_bytes',0)
            value=f'{val:.1f}%' if key=='cpu' else size_fmt(val)
            print(f"    {paint(f"{p['pid']:>7}",args,0.6)} {bar(val,max(mx,1),17,args.palette,colored(args))} {value:>10} {p['name'][:40]}")
    print('  '+separator(args,78))
    print(f"  LIFECYCLE  new {len(snapshot['births'])}  exited {len(snapshot['exits'])}  PID reuse {len(snapshot['pid_reuse'])}  unreadable {snapshot['errors']}")

def pressure(snapshot,args):
    headline('KERNEL PRESSURE STALL INFORMATION',snapshot,args)
    psi=snapshot.get('system',{}).get('pressure',{})
    if not psi:
        print('PSI metrics unavailable on this procfs mount')
        return
    print('  RESOURCE      MODE      AVG10      AVG60     AVG300       TOTAL STALL')
    print(separator(args,85))
    for resource,groups in psi.items():
        for mode,data in groups.items():
            a=data.get('avg10',0)
            color=state_color('Z' if a>20 else 'D' if a>5 else 'R')
            text=f"  {resource:<12}  {mode:<6}  {a:>8.2f}%  {data.get('avg60',0):>8.2f}%  {data.get('avg300',0):>8.2f}%  {data.get('total',0)/1e6:>12.2f}s"
            print(tint(text,color,colored(args)))
    print('\n  PSI averages describe stalled wall-clock time, not process CPU utilization')

def heatmap(snapshot,args):
    headline('PROCESS HEATMAP  /  COMPUTE AND MEMORY',snapshot,args)
    rows=ordered([p for p in snapshot['records'] if p['type']=='process'],args.sort,args.limit)
    if not rows:
        print('No visible processes')
        return
    maxcpu=max(100,max(p['cpu'] for p in rows))
    maxrss=max(1,max(p['rss'] for p in rows))
    glyphs=' ▁▂▃▄▅▆▇█'
    print(paint('     PID STATE   CPU HEAT FIELD             MEMORY HEAT FIELD           COMMAND',args,0.1,True))
    print(separator(args,106))
    for p in rows:
        cpu=p['cpu']/maxcpu
        mem=p['rss']/maxrss
        def field(f):
            return ''.join(paint(glyphs[min(8,max(0,int(8*f*(0.45+0.55*(i+1)/25))))],args,clamp(f+0.1*i/25,0,1)) for i in range(25))
        print(f"{p['pid']:8} {state_text(p['state'],args)}      {field(cpu)}  {field(mem)}  {p['name'][:40]}")
    print('\n  CPU heat is scaled to at least one logical CPU; RSS heat is relative to visible processes')

def io_view(snapshot,args):
    headline('PROCESS I/O FORENSICS',snapshot,args)
    rows=ordered([p for p in snapshot['records'] if p['type']=='process'],'io',args.limit)
    print(paint(f"{'PID':>8} {'READ Δ':>12} {'WRITE Δ':>12} {'READ TOTAL':>13} {'WRITE TOTAL':>13}  COMMAND",args,0.1,True))
    print(separator(args,108))
    for p in rows:
        io=p['io']; delta=p['io_delta']
        print(f"{p['pid']:8} {paint(f"{size_fmt(delta.get('read_bytes',0)):>12}",args,0.7)} {paint(f"{size_fmt(delta.get('write_bytes',0)):>12}",args,0.3)} {size_fmt(io.get('read_bytes',0)):>13} {size_fmt(io.get('write_bytes',0)):>13}  {p['name'][:50]}")
    print('\n  I/O deltas require consecutive samples; the first sample reports zero deltas')

def state_view(snapshot,args):
    headline('SCHEDULER STATE DISTRIBUTION',snapshot,args)
    procs=[p for p in snapshot['records'] if p['type']=='process']
    counts=collections.Counter(p['state'] for p in procs)
    for state,count in sorted(counts.items(),key=lambda x:-x[1]):
        pct=100*count/max(1,len(procs))
        print(f"  {state_text(state,args)} {STATES.get(state,'unknown'):<16} {bar(count,max(1,len(procs)),48,args.palette,colored(args))} {count:>6}  {pct:5.1f}%")
    print('\n  Kernel process states are instantaneous observations')

def table(snapshot,args):
    records=ordered(snapshot['records'],args.sort,args.limit)
    use_color=args.color=='always' or (args.color=='auto' and sys.stdout.isatty() and not os.environ.get('NO_COLOR'))
    print(tint(f"PROCSTAT  {snapshot['timestamp']}   processes {snapshot['count']}   cores {snapshot['cores']}   scan {snapshot['scan_seconds']:.3f}s",PALETTES[args.palette][0],use_color))
    print(f"CPU {snapshot['total_cpu']:.1f}%   RSS {size_fmt(snapshot['total_rss'])}   new {len(snapshot['births'])}   exited {len(snapshot['exits'])}   errors {snapshot['errors']}")
    print(f"{'PID':>7} {'PPID':>7} {'S':1} {'CPU%':>7} {'MEMORY':>10} {'TIME':>10} {'THR':>5} {'CPU ACTIVITY':<18} COMMAND")
    print('─'*106)
    maxcpu=max((p['cpu'] for p in records),default=1)
    for p in records:
        name=('  ↳ ' if p['type']=='thread' else '')+p['name']
        c=tint(f"{p['cpu']:7.1f}",gradient(p['cpu']/max(maxcpu,1),args.palette),use_color)
        print(f"{p['pid']:7} {p['ppid']:7} {state_text(p['state'],args)} {c} {size_fmt(p['memory']):>10} {p['cpu_seconds']:10.1f} {p['threads']:5} {bar(p['cpu'],max(maxcpu,1),18,args.palette,use_color)} {name}")

def tree(snapshot,args):
    processes=[p for p in snapshot['records'] if p['type']=='process']
    by_pid={p['pid']:p for p in processes}; children=collections.defaultdict(list); roots=[]
    for p in processes:
        if p['ppid'] in by_pid and p['ppid']!=p['pid']: children[p['ppid']].append(p)
        else: roots.append(p)
    threadmap=collections.defaultdict(list)
    for p in snapshot['records']:
        if p['type']=='thread': threadmap[p['tgid']].append(p)
    seen=set(); printed=0
    def visit(p,prefix='',last=True,depth=0):
        nonlocal printed
        if p['pid'] in seen or printed>=args.limit or depth>args.depth: return
        seen.add(p['pid']); printed+=1
        print(f"{paint(prefix+('└─' if last else '├─'),args,0.4)} {paint(p['pid'],args,0.7)} {state_text(p['state'],args)} CPU={p['cpu']:.1f}% RSS={size_fmt(p['rss'])} {p['name']}")
        next_prefix=prefix+('   ' if last else '│  ')
        nodes=sorted(children[p['pid']],key=lambda q:(-q['cpu'],q['pid']))
        if args.threads: nodes+=sorted(threadmap[p['pid']],key=lambda q:q['pid'])
        for i,child in enumerate(nodes):
            if child['type']=='thread':
                if printed>=args.limit: break
                printed+=1
                print(f"{next_prefix}{'└─' if i==len(nodes)-1 else '├─'} {child['pid']} [thread] {child['name']} CPU={child['cpu']:.1f}%")
            else: visit(child,next_prefix,i==len(nodes)-1,depth+1)
    for i,p in enumerate(sorted(roots,key=lambda q:q['pid'])):
        visit(p,'',i==len(roots)-1)

def summary(snapshot,args):
    procs=[p for p in snapshot['records'] if p['type']=='process']
    print(f"Process census: {len(procs)}  RSS {size_fmt(snapshot['total_rss'])}  CPU {snapshot['total_cpu']:.1f}%")
    print('States: '+', '.join(f'{k}={v}' for k,v in sorted(collections.Counter(p['state'] for p in procs).items())))
    for title,key in [('CPU','cpu'),('MEMORY','mem'),('I/O','io'),('THREADS','threads')]:
        print('\n'+title)
        for p in ordered(procs,key,min(args.limit,10)):
            value={'cpu':f"{p['cpu']:.1f}%",'mem':size_fmt(p['rss']),'io':size_fmt(p['io_delta'].get('read_bytes',0)+p['io_delta'].get('write_bytes',0)),'threads':str(p['threads'])}[key]
            print(f"  {p['pid']:>7} {value:>12} {p['name']}")

def topology(snapshot,args):
    procs=ordered([p for p in snapshot['records'] if p['type']=='process'],args.sort,args.limit)
    use_color=args.color=='always' or (args.color=='auto' and sys.stdout.isatty() and not os.environ.get('NO_COLOR'))
    maxmem=max((p['rss'] for p in procs),default=1)
    maxcpu=max((p['cpu'] for p in procs),default=1)
    headline('PROCESS CONSTELLATION  /  CPU AND RESIDENT MEMORY',snapshot,args)
    print(f"{'PID':>7} {'CPU LUMINANCE':<34} {'RSS DENSITY':<34} NAME")
    for p in procs:
        print(f"{p['pid']:7} {bar(p['cpu'],max(maxcpu,1),24,args.palette,use_color)} {bar(p['rss'],maxmem,24,args.palette,use_color)} {p['name'][:45]}")

def diff_snapshots(before,after,args):
    old={p['identity']:p for p in before['records'] if p['type']=='process'}
    new={p['identity']:p for p in after['records'] if p['type']=='process'}
    rows=[]
    for key in old.keys()|new.keys():
        a=old.get(key); b=new.get(key)
        rows.append({'pid':(b or a)['pid'],'name':(b or a)['name'],'status':'new' if a is None else 'exited' if b is None else 'persisting',
                     'rss_delta':(b['rss'] if b else 0)-(a['rss'] if a else 0),
                     'cpu_seconds_delta':round((b['cpu_seconds'] if b else 0)-(a['cpu_seconds'] if a else 0),3),
                     'threads_delta':(b['threads'] if b else 0)-(a['threads'] if a else 0)})
    rows.sort(key=lambda r:(-abs(r['rss_delta']),r['pid']))
    if args.format=='json': print(json.dumps({'schema':'procstat-python/diff-v1','before':before.get('timestamp'),'after':after.get('timestamp'),'rows':rows},indent=2)); return
    print(f"BASELINE DIFF  {before.get('timestamp','?')} → {after.get('timestamp','?')}")
    print(f"{'PID':>7} {'STATUS':<12} {'RSS DELTA':>14} {'CPU TIME Δ':>12} {'THR Δ':>7} NAME")
    for r in rows[:args.limit]:
        print(f"{r['pid']:7} {r['status']:<12} {r['rss_delta']/1048576:+13.2f}M {r['cpu_seconds_delta']:+12.2f} {r['threads_delta']:+7} {r['name']}")

def load_snapshot(path):
    with open(path,encoding='utf-8') as f: data=json.load(f)
    if data.get('schema')!='procstat-python/v2' or not isinstance(data.get('records'),list):
        raise ValueError('unsupported snapshot schema')
    return data

def atomic_json(path,data):
    target=pathlib.Path(path); target.parent.mkdir(parents=True,exist_ok=True)
    temp=target.with_name(target.name+'.tmp.'+str(os.getpid()))
    try:
        with open(temp,'w',encoding='utf-8') as f:
            json.dump(data,f,indent=2,ensure_ascii=False); f.write('\n')
        os.replace(temp,target)
    finally:
        if temp.exists(): temp.unlink()

def export_csv(path,snapshot,append=False):
    columns=['timestamp','pid','tgid','ppid','type','state','cpu','cpu_seconds','rss','vsize','threads','priority','nice','processor','ctx_voluntary','ctx_involuntary','name']
    target=pathlib.Path(path); target.parent.mkdir(parents=True,exist_ok=True)
    exists=target.exists() and target.stat().st_size>0
    with open(target,'a' if append else 'w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=columns)
        if not append or not exists: writer.writeheader()
        for p in snapshot['records']:
            writer.writerow({k:snapshot['timestamp'] if k=='timestamp' else p.get(k) for k in columns})



COZY_THEMES = {
    'hearth': {'warm': (255, 194, 142), 'soft': (196, 157, 170), 'dim': (130, 118, 131), 'cool': (149, 188, 178), 'alert': (238, 132, 120)},
    'lantern': {'warm': (255, 215, 149), 'soft': (181, 192, 158), 'dim': (128, 139, 127), 'cool': (151, 196, 189), 'alert': (231, 149, 118)},
    'dusk': {'warm': (225, 179, 199), 'soft': (171, 165, 200), 'dim': (119, 132, 159), 'cool': (141, 187, 207), 'alert': (229, 144, 151)},
    'cocoa': {'warm': (225, 187, 151), 'soft': (180, 153, 146), 'dim': (125, 117, 116), 'cool': (155, 185, 174), 'alert': (224, 138, 120)},
    'moss': {'warm': (221, 199, 151), 'soft': (173, 199, 155), 'dim': (122, 145, 130), 'cool': (152, 194, 186), 'alert': (221, 147, 128)},
    'rosewood': {'warm': (247, 186, 168), 'soft': (211, 157, 183), 'dim': (142, 121, 148), 'cool': (166, 192, 185), 'alert': (230, 132, 142)},
}

COZY_SYMBOLS = {
    'diamond': '◇',
    'circle': '◌',
    'star': '✧',
    'line': '─',
    'leaf': '❧',
    'dot': '·',
    'vertical': '│',
    'corner': '╰',
}


def terminal_width(default=100):
    try:
        import shutil
        return max(64, min(180, shutil.get_terminal_size((default, 28)).columns))
    except (OSError, ValueError):
        return default


def theme_for(args):
    if args.palette in COZY_THEMES:
        return COZY_THEMES[args.palette]
    first, second = PALETTES[args.palette]
    return {'warm': first, 'soft': second, 'dim': (135, 140, 148), 'cool': second, 'alert': (245, 130, 135)}


def cozy_color(text, args, role='warm', bold=False):
    color = theme_for(args).get(role, theme_for(args)['warm'])
    if colored(args):
        prefix = '\x1b[1m' if bold else ''
        return prefix + tint(str(text), color, True) + ('\x1b[0m' if bold else '')
    return str(text)


def visible_length(text):
    return len(re.sub(r'\x1b\[[0-9;]*m', '', str(text)))


def padded(text, width, align='left'):
    missing = max(0, width - visible_length(text))
    return (' ' * missing + text) if align == 'right' else (text + ' ' * missing)


def cozy_rule(args, width=None, character='─'):
    width = width or terminal_width()
    return cozy_color(character * max(1, width - 2), args, 'dim')


def cozy_header(title, snapshot, args, subtitle=None):
    width = terminal_width()
    print()
    print(cozy_color('╭' + '─' * (width - 2) + '╮', args, 'dim'))
    name = f'  {title.upper()}  '
    print(cozy_color('│', args, 'dim') + cozy_color(padded(name, width - 2), args, 'warm', True) + cozy_color('│', args, 'dim'))
    detail = subtitle or 'a quiet observatory for the living Linux system'
    print(cozy_color('│', args, 'dim') + cozy_color(padded('  ' + detail[:width - 7], width - 2), args, 'soft') + cozy_color('│', args, 'dim'))
    print(cozy_color('╰' + '─' * (width - 2) + '╯', args, 'dim'))
    print(cozy_color(f"  {snapshot.get('timestamp', '')}   ·   {snapshot.get('count', 0)} processes   ·   {snapshot.get('cores', 0)} logical CPUs", args, 'dim'))
    print()


def cozy_section(title, args, symbol='◇'):
    print()
    print(cozy_color(f'  {symbol}  {title}', args, 'warm', True))
    print('  ' + cozy_rule(args, min(terminal_width() - 4, 72)))


def soft_meter(value, maximum, width, args, role='warm', filled='━', empty='·'):
    maximum = max(float(maximum), 0.000001)
    fraction = clamp(float(value) / maximum, 0, 1)
    amount = min(width, max(0, round(fraction * width)))
    return cozy_color(filled * amount, args, role) + cozy_color(empty * (width - amount), args, 'dim')


def short_name(process, width=44):
    name = safe(process.get('name', process.get('comm', 'unknown')))
    return name if len(name) <= width else name[:max(1, width - 1)] + '…'


def process_rows(snapshot):
    return [record for record in snapshot.get('records', []) if record.get('type') == 'process']


def quantile(values, q):
    values = sorted(values)
    if not values:
        return 0.0
    position = (len(values) - 1) * clamp(q, 0, 1)
    low = int(position)
    high = min(len(values) - 1, low + 1)
    return values[low] + (values[high] - values[low]) * (position - low)


def distribution(values):
    if not values:
        return {'count': 0, 'min': 0, 'median': 0, 'p90': 0, 'p99': 0, 'max': 0, 'mean': 0}
    return {
        'count': len(values),
        'min': min(values),
        'median': quantile(values, 0.5),
        'p90': quantile(values, 0.9),
        'p99': quantile(values, 0.99),
        'max': max(values),
        'mean': sum(values) / len(values),
    }


def histogram(values, buckets=12, logarithmic=False):
    if not values:
        return []
    transformed = [math.log1p(max(0, v)) if logarithmic else max(0, v) for v in values]
    maximum = max(transformed) or 1
    counts = [0] * buckets
    for value in transformed:
        index = min(buckets - 1, int(value / maximum * buckets))
        counts[index] += 1
    return counts


def summarize_processes(snapshot):
    rows = process_rows(snapshot)
    state_counts = collections.Counter(p.get('state', '?') for p in rows)
    return {
        'cpu': distribution([p.get('cpu', 0) for p in rows]),
        'rss': distribution([p.get('rss', 0) for p in rows]),
        'threads': distribution([p.get('threads', 0) for p in rows]),
        'states': dict(state_counts),
        'io_read': sum(p.get('io_delta', {}).get('read_bytes', 0) for p in rows),
        'io_write': sum(p.get('io_delta', {}).get('write_bytes', 0) for p in rows),
        'context_switches': sum(p.get('ctx_delta', 0) for p in rows),
    }


def system_memory(snapshot):
    memory = snapshot.get('system', {}).get('memory', {})
    total = memory.get('MemTotal', 0)
    available = memory.get('MemAvailable', 0)
    return {'total': total, 'available': available, 'used': max(0, total - available), 'ratio': (total - available) / total if total else 0}


def format_duration(seconds):
    seconds = max(0, int(seconds or 0))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f'{days}d {hours}h {minutes}m'
    if hours:
        return f'{hours}h {minutes}m'
    if minutes:
        return f'{minutes}m {seconds}s'
    return f'{seconds}s'


def cozy_overview(snapshot, args, history=None):
    cozy_header('Hearth Observatory', snapshot, args, 'warm light over process activity, memory and kernel pressure')
    rows = process_rows(snapshot)
    memory = system_memory(snapshot)
    stats = summarize_processes(snapshot)
    uptime = format_duration(snapshot.get('uptime'))
    print('  ' + cozy_color('SYSTEM UPTIME', args, 'soft') + f'  {uptime}')
    print('  ' + cozy_color('SCAN LATENCY', args, 'soft') + f"  {snapshot.get('scan_seconds', 0)*1000:.1f} ms")
    cozy_section('Memory garden', args, '❧')
    print('  ' + soft_meter(memory['used'], max(memory['total'], 1), 46, args, 'warm'))
    print(f"  {size_fmt(memory['used'])} used    {size_fmt(memory['available'])} available    {size_fmt(memory['total'])} total")
    cozy_section('Compute glow', args, '✧')
    maxcpu = max(100, snapshot.get('cores', 1) * 100)
    print('  ' + soft_meter(snapshot.get('total_cpu', 0), maxcpu, 46, args, 'cool'))
    print(f"  {snapshot.get('total_cpu', 0):.2f}% aggregate process CPU   ·   {snapshot.get('cores', 1)} logical CPUs")
    if history:
        print('  ' + cozy_color(sparkline(history, 54), args, 'soft'))
    cozy_section('The sleeping forest', args, '◇')
    states = stats['states']
    for state, count in sorted(states.items(), key=lambda item: -item[1]):
        label = STATES.get(state, 'other')
        print(f"  {cozy_color(state, args, 'warm')}  {label:<16} {soft_meter(count, max(1, len(rows)), 35, args, 'soft')} {count:>6}")
    cozy_section('Gentle movements', args, '◌')
    print(f"  New identities   {len(snapshot.get('births', [])):>6}    Departures   {len(snapshot.get('exits', [])):>6}")
    print(f"  PID reuse        {len(snapshot.get('pid_reuse', [])):>6}    Unreadable   {snapshot.get('errors', 0):>6}")
    print(f"  I/O read         {size_fmt(stats['io_read']):>9}    I/O write    {size_fmt(stats['io_write']):>9}")
    cozy_section('Quietly brightest', args, '✧')
    for process in ordered(rows, 'cpu', min(args.limit, 8)):
        glow = soft_meter(process['cpu'], max(100, stats['cpu']['max']), 17, args, 'warm')
        print(f"  {process['pid']:>7}  {glow}  {process['cpu']:>6.1f}%  {short_name(process, 42)}")
    print()


def cozy_lanterns(snapshot, args):
    cozy_header('Lantern Walk', snapshot, args, 'each process a small light along the scheduler path')
    rows = ordered(process_rows(snapshot), args.sort, args.limit)
    maximum = max([p.get('cpu', 0) for p in rows] + [100])
    print(cozy_color('  PID       LIGHT                          CPU       RSS        STATE   COMMAND', args, 'soft'))
    print('  ' + cozy_rule(args, 96))
    for index, process in enumerate(rows):
        cpu = process.get('cpu', 0)
        shade = 'warm' if cpu > 10 else 'cool' if cpu > 1 else 'dim'
        ornament = '✦' if cpu > 25 else '✧' if cpu > 2 else '·'
        light = soft_meter(cpu, maximum, 27, args, shade, '●', '·')
        print(f"  {process['pid']:>7}  {cozy_color(ornament, args, shade)} {light}  {cpu:>6.1f}%  {size_fmt(process['rss']):>9}  {state_text(process['state'], args)}  {short_name(process, 44)}")
        if index and (index + 1) % 10 == 0:
            print(cozy_color('  ' + '· ' * 40, args, 'dim'))
    print()
    print(cozy_color('  The glow represents sampled CPU utilization, not system-wide CPU share', args, 'dim'))


def cozy_garden(snapshot, args):
    cozy_header('Process Garden', snapshot, args, 'a quiet field of memory footprints and CPU activity')
    rows = ordered(process_rows(snapshot), args.sort, args.limit)
    if not rows:
        print('  No processes visible')
        return
    maxrss = max(p['rss'] for p in rows) or 1
    maxcpu = max(max(p['cpu'] for p in rows), 100)
    for process in rows:
        cpu = process['cpu'] / maxcpu
        rss = process['rss'] / maxrss
        stem = '│' * min(8, 1 + round(cpu * 7))
        petals = '✿' if cpu > 30 else '✧' if cpu > 5 else '·'
        print(f"  {cozy_color(petals, args, 'warm')} {process['pid']:>7} {cozy_color(stem, args, 'soft'):<16} {soft_meter(rss, 1, 23, args, 'cool')} {size_fmt(process['rss']):>9}  {short_name(process, 44)}")
    print()
    print(cozy_color('  Stems encode CPU activity; the horizontal field represents relative resident memory', args, 'dim'))


def cozy_moonlight(snapshot, args):
    cozy_header('Moonlight Distribution', snapshot, args, 'percentiles and quiet statistical landscapes')
    rows = process_rows(snapshot)
    measures = (
        ('CPU utilization', [p['cpu'] for p in rows], '%', False),
        ('Resident memory', [p['rss'] for p in rows], 'bytes', True),
        ('Thread counts', [p['threads'] for p in rows], 'threads', True),
        ('Context switches', [p.get('ctx_delta', 0) for p in rows], 'switches', True),
    )
    for title, values, unit, logarithmic in measures:
        cozy_section(title, args, '☾')
        stats = distribution(values)
        if unit == 'bytes':
            show = lambda v: size_fmt(v)
        elif unit == '%':
            show = lambda v: f'{v:.2f}%'
        else:
            show = lambda v: f'{v:.1f}'
        print(f"  Median {show(stats['median'])}   ·   P90 {show(stats['p90'])}   ·   P99 {show(stats['p99'])}   ·   Max {show(stats['max'])}")
        counts = histogram(values, 16, logarithmic)
        maximum = max(counts, default=1) or 1
        for index, count in enumerate(counts):
            print(f"  {index+1:>2}  {soft_meter(count, maximum, 33, args, 'soft')}  {count:>5}")
    print()
    print(cozy_color('  Logarithmic buckets emphasize the low end of heavy-tailed distributions', args, 'dim'))


def cozy_breath(snapshot, args):
    cozy_header('Kernel Breathing', snapshot, args, 'pressure-stall signals, a measure of waiting rather than work')
    pressure_data = snapshot.get('system', {}).get('pressure', {})
    if not pressure_data:
        print('  Pressure telemetry is unavailable in this environment')
        return
    for resource in ('cpu', 'memory', 'io'):
        groups = pressure_data.get(resource, {})
        cozy_section(resource.capitalize() + ' pressure', args, '◌')
        if not groups:
            print('  Not available')
            continue
        for mode, metrics in sorted(groups.items()):
            avg10 = metrics.get('avg10', 0)
            avg60 = metrics.get('avg60', 0)
            avg300 = metrics.get('avg300', 0)
            print(f"  {mode:<5}  {soft_meter(avg10, 100, 38, args, 'alert' if avg10 > 10 else 'cool')}")
            print(f"         10s {avg10:>6.2f}%    60s {avg60:>6.2f}%    300s {avg300:>6.2f}%")
            print(f"         cumulative stalled time {metrics.get('total', 0)/1000000:.2f}s")
    print()
    print(cozy_color('  PSI percentages are wall-clock stall fractions, not CPU utilization', args, 'dim'))


def cozy_river(snapshot, args):
    cozy_header('I/O River', snapshot, args, 'processes carrying bytes through the kernel')
    rows = ordered(process_rows(snapshot), 'io', args.limit)
    maximum = max([p.get('io_delta', {}).get('read_bytes', 0) + p.get('io_delta', {}).get('write_bytes', 0) for p in rows] + [1])
    print(cozy_color('       PID    READ FLOW                      WRITE FLOW                     COMMAND', args, 'soft'))
    print('  ' + cozy_rule(args, 96))
    for process in rows:
        io = process.get('io_delta', {})
        read = io.get('read_bytes', 0)
        write = io.get('write_bytes', 0)
        print(f"  {process['pid']:>8}  {soft_meter(read, maximum, 23, args, 'cool')}  {soft_meter(write, maximum, 23, args, 'warm')}  {short_name(process, 32)}")
        print(cozy_color(f"            read {size_fmt(read):>9}    write {size_fmt(write):>9}", args, 'dim'))
    print()
    print(cozy_color('  Delta values require consecutive scans; the initial sample has no I/O baseline', args, 'dim'))


def cozy_threads(snapshot, args):
    cozy_header('Thread Weave', snapshot, args, 'concurrency patterns and thread density')
    rows = ordered(process_rows(snapshot), 'threads', args.limit)
    maximum = max([p['threads'] for p in rows] + [1])
    for process in rows:
        density = soft_meter(process['threads'], maximum, 38, args, 'soft')
        print(f"  {process['pid']:>7}  {density}  {process['threads']:>5}  {short_name(process, 45)}")
    print()
    print(cozy_color('  Thread counts come from /proc/[pid]/stat and do not require --threads', args, 'dim'))


def cozy_census(snapshot, args):
    cozy_header('Process Census', snapshot, args, 'a compact catalogue of the current system')
    rows = process_rows(snapshot)
    stats = summarize_processes(snapshot)
    cozy_section('Population', args)
    print(f"  Processes        {len(rows):>8}")
    print(f"  Thread rows      {snapshot.get('thread_rows', 0):>8}")
    print(f"  Unreadable       {snapshot.get('errors', 0):>8}")
    print(f"  Resident sum     {size_fmt(snapshot.get('total_rss', 0)):>8}")
    print(f"  CPU sum          {snapshot.get('total_cpu', 0):>7.1f}%")
    cozy_section('Percentile sketch', args)
    for name, values in [('CPU', stats['cpu']), ('RSS', stats['rss']), ('Threads', stats['threads'])]:
        fmt = size_fmt if name == 'RSS' else lambda x: f'{x:.2f}'
        print(f"  {name:<12} median {fmt(values['median']):>11}   p90 {fmt(values['p90']):>11}   p99 {fmt(values['p99']):>11}")
    cozy_section('Process states', args)
    for state, count in sorted(stats['states'].items(), key=lambda item: -item[1]):
        print(f"  {state_text(state, args)}  {STATES.get(state, 'unknown'):<18} {count:>8}")
    print()


def cozy_identity(snapshot, args):
    cozy_header('Identity Ledger', snapshot, args, 'process identity, PID reuse and lifecycle changes')
    cozy_section('Births observed', args, '✧')
    births = set(snapshot.get('births', []))
    for process in process_rows(snapshot):
        if process['pid'] in births:
            print(f"  {process['pid']:>8}  {process['identity']:<24}  {short_name(process, 52)}")
    if not births:
        print('  No new identities in this scan')
    cozy_section('Departures observed', args, '◇')
    for pid in snapshot.get('exits', []):
        print(f'  PID {pid} no longer present')
    if not snapshot.get('exits'):
        print('  No departures observed')
    cozy_section('PID reuse', args, '◌')
    for pid in snapshot.get('pid_reuse', []):
        print(cozy_color(f'  PID {pid} has a new process start identity', args, 'alert'))
    if not snapshot.get('pid_reuse'):
        print('  No PID reuse observed')
    print()
    print(cozy_color('  Lifecycle observations require at least two scans by the same collector', args, 'dim'))


def cozy_report(snapshot, args):
    cozy_overview(snapshot, args)
    cozy_census(snapshot, args)
    cozy_moonlight(snapshot, args)
    cozy_breath(snapshot, args)
    cozy_threads(snapshot, args)


def snapshot_insights(snapshot):
    stats = summarize_processes(snapshot)
    memory = system_memory(snapshot)
    rows = process_rows(snapshot)
    findings = []
    if memory['ratio'] > 0.9:
        findings.append({'level': 'warning', 'code': 'memory_pressure', 'message': 'System memory use exceeds 90 percent'})
    if stats['states'].get('D', 0) >= 3:
        findings.append({'level': 'notice', 'code': 'uninterruptible_sleep', 'message': 'Multiple processes are in uninterruptible sleep'})
    if stats['states'].get('Z', 0):
        findings.append({'level': 'notice', 'code': 'zombies', 'message': 'Zombie processes are present'})
    if snapshot.get('pid_reuse'):
        findings.append({'level': 'notice', 'code': 'pid_reuse', 'message': 'PID reuse was observed between samples'})
    for process in sorted(rows, key=lambda p: -p['rss'])[:5]:
        if memory['total'] and process['rss'] / memory['total'] > 0.2:
            findings.append({'level': 'notice', 'code': 'large_rss', 'pid': process['pid'], 'message': 'Process RSS exceeds 20 percent of physical memory'})
    return findings


def cozy_findings(snapshot, args):
    cozy_header('Quiet Signals', snapshot, args, 'heuristic observations, not diagnoses')
    findings = snapshot_insights(snapshot)
    if not findings:
        print(cozy_color('  ◇  No configured heuristic thresholds were crossed', args, 'cool'))
        return
    for finding in findings:
        role = 'alert' if finding['level'] == 'warning' else 'warm'
        print(cozy_color(f"  ◇  {finding['code']:<25} {finding['message']}", args, role))
    print()
    print(cozy_color('  These signals are heuristic and require operational context', args, 'dim'))


def save_svg_art(path, snapshot, args):
    import html
    rows = ordered(process_rows(snapshot), args.sort, min(args.limit, 120))
    width = 1100
    height = max(320, 185 + len(rows) * 23)
    theme = theme_for(args)
    def rgb(value):
        return '#%02x%02x%02x' % value
    warm = rgb(theme['warm'])
    soft = rgb(theme['soft'])
    dim = rgb(theme['dim'])
    cool = rgb(theme['cool'])
    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#171a20"/>',
        f'<rect x="28" y="28" width="1044" height="{height-56}" rx="18" fill="#22242c" stroke="{dim}" stroke-opacity=".55"/>',
        f'<text x="62" y="78" fill="{warm}" font-size="28" font-family="monospace">PROCSTAT  /  THE QUIET OBSERVATORY</text>',
        f'<text x="62" y="109" fill="{soft}" font-size="15" font-family="monospace">{html.escape(str(snapshot.get("timestamp", "")))}</text>',
        f'<text x="62" y="151" fill="{dim}" font-size="13" font-family="monospace">PID    CPU LIGHT                         MEMORY FIELD                       PROCESS</text>',
    ]
    maxrss = max([p['rss'] for p in rows] + [1])
    maxcpu = max([p['cpu'] for p in rows] + [100])
    for index, process in enumerate(rows):
        y = 178 + index * 23
        cpu = max(0, process['cpu']) / maxcpu
        rss = max(0, process['rss']) / maxrss
        name = html.escape(short_name(process, 45))
        elements.append(f'<text x="62" y="{y}" fill="{soft}" font-size="13" font-family="monospace">{process["pid"]:>7}</text>')
        elements.append(f'<rect x="155" y="{y-12}" width="270" height="12" rx="5" fill="#34363d"/>')
        elements.append(f'<rect x="155" y="{y-12}" width="{round(270*cpu)}" height="12" rx="5" fill="{warm}"/>')
        elements.append(f'<rect x="452" y="{y-12}" width="270" height="12" rx="5" fill="#34363d"/>')
        elements.append(f'<rect x="452" y="{y-12}" width="{round(270*rss)}" height="12" rx="5" fill="{cool}"/>')
        elements.append(f'<text x="744" y="{y}" fill="{soft}" font-size="12" font-family="monospace">{name}</text>')
    elements.append('</svg>')
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('\n'.join(elements) + '\n', encoding='utf-8')


def write_markdown_report(path, snapshot):
    stats = summarize_processes(snapshot)
    lines = [
        '# procstat-python System Observation',
        '',
        f"Captured: {snapshot.get('timestamp', '')}",
        '',
        '## Overview',
        '',
        f"- Processes: {snapshot.get('count', 0)}",
        f"- CPU utilization: {snapshot.get('total_cpu', 0):.2f}%",
        f"- Aggregate process RSS: {size_fmt(snapshot.get('total_rss', 0))}",
        f"- Logical CPUs: {snapshot.get('cores', 0)}",
        f"- Unreadable processes: {snapshot.get('errors', 0)}",
        '',
        '## Scheduler states',
        '',
    ]
    for state, count in sorted(stats['states'].items()):
        lines.append(f'- {state} ({STATES.get(state, "unknown")}): {count}')
    lines.extend(['', '## Highest CPU utilization', '', '| PID | CPU % | RSS | Process |', '|---:|---:|---:|---|'])
    for process in ordered(process_rows(snapshot), 'cpu', 15):
        name = short_name(process, 80).replace('|', '&#124;')
        lines.append(f"| {process['pid']} | {process['cpu']:.2f} | {size_fmt(process['rss'])} | {name} |")
    lines.extend(['', '## Heuristic observations', ''])
    for finding in snapshot_insights(snapshot):
        lines.append(f"- {finding['level']}: {finding['message']}")
    if not snapshot_insights(snapshot):
        lines.append('- No configured thresholds crossed')
    lines.extend(['', 'Observations are point-in-time estimates and are not a substitute for full system profiling', ''])
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('\n'.join(lines), encoding='utf-8')


def render_cozy(command, snapshot, args, history=None):
    views = {
        'hearth': lambda: cozy_overview(snapshot, args, history),
        'lanterns': lambda: cozy_lanterns(snapshot, args),
        'garden': lambda: cozy_garden(snapshot, args),
        'moonlight': lambda: cozy_moonlight(snapshot, args),
        'breathing': lambda: cozy_breath(snapshot, args),
        'river': lambda: cozy_river(snapshot, args),
        'weave': lambda: cozy_threads(snapshot, args),
        'census': lambda: cozy_census(snapshot, args),
        'identities': lambda: cozy_identity(snapshot, args),
        'signals': lambda: cozy_findings(snapshot, args),
        'report': lambda: cozy_report(snapshot, args),
    }
    render = views.get(command)
    if render is None:
        return False
    render()
    return True

def parser_build():
    p=argparse.ArgumentParser(description='procstat-python: Linux process forensics and terminal art-technology')
    p.add_argument('command',nargs='?',default='top',choices=['top','tree','summary','topology','dashboard','heatmap','pressure','io','states','watch','snapshot','baseline','diff','inspect','hearth','lanterns','garden','moonlight','breathing','river','weave','census','identities','signals','report'])
    p.add_argument('--proc-root',default='/proc',help='Alternate procfs fixture directory')
    p.add_argument('--limit',type=int,default=25)
    p.add_argument('--sort',choices=['cpu','mem','pid','command','time','io','threads'],default='cpu')
    p.add_argument('--interval',type=float,default=2)
    p.add_argument('--count',type=int,default=0,help='Watch iterations, 0 means unlimited')
    p.add_argument('--view',choices=['top','dashboard','heatmap','topology','pressure','io','states','summary','hearth','lanterns','garden','moonlight','breathing','river','weave','census','identities','signals','report'],default='hearth',help='Visual display used by watch mode')
    p.add_argument('--watch',nargs='?',const=2,type=float,default=None,metavar='SECONDS',help='Legacy alias for watch mode')
    p.add_argument('--threads',action='store_true'); p.add_argument('--zombie',action='store_true')
    p.add_argument('--vm-size',action='store_true'); p.add_argument('--kb',action='store_true'); p.add_argument('--mb',action='store_true')
    p.add_argument('--thread-limit',type=int,default=1000); p.add_argument('--max-scan',type=int,default=131072)
    p.add_argument('--depth',type=int,default=32); p.add_argument('--cmd-length',type=int,default=120)
    p.add_argument('--palette',choices=list(PALETTES),default='hearth'); p.add_argument('--color',choices=['auto','always','never'],default='auto')
    p.add_argument('--format',choices=['table','json','jsonl','csv'],default='table')
    p.add_argument('--output',help='Output file for snapshots or exported records')
    p.add_argument('--baseline',help='Saved JSON snapshot to compare against')
    p.add_argument('--pid',type=int,help='Process ID for inspect')
    p.add_argument('--svg',help='Export cozy process atlas as SVG')
    p.add_argument('--markdown',help='Export a Markdown observation report')
    p.add_argument('--no-io',action='store_true'); p.add_argument('--verbose',action='store_true')
    p.add_argument('--version',action='version',version=VERSION)
    return p

def emit(snapshot,args):
    if args.format=='json': print(json.dumps(snapshot,indent=2,ensure_ascii=False)); return
    if args.format=='jsonl': print(json.dumps(snapshot,ensure_ascii=False,separators=(',',':'))); return
    if args.format=='csv':
        w=csv.writer(sys.stdout); w.writerow(['pid','ppid','type','state','cpu','rss','vsize','threads','name'])
        for r in snapshot['records']: w.writerow([r.get(k) for k in ('pid','ppid','type','state','cpu','rss','vsize','threads','name')])
        return
    if render_cozy(args.command,snapshot,args,getattr(args,'history',None)): return
    if args.command=='tree': tree(snapshot,args)
    elif args.command=='summary': summary(snapshot,args)
    elif args.command=='topology': topology(snapshot,args)
    elif args.command=='dashboard': dashboard(snapshot,args,getattr(args,'history',None))
    elif args.command=='heatmap': heatmap(snapshot,args)
    elif args.command=='pressure': pressure(snapshot,args)
    elif args.command=='io': io_view(snapshot,args)
    elif args.command=='states': state_view(snapshot,args)
    elif args.command=='inspect':
        rows=[r for r in snapshot['records'] if r['pid']==args.pid or (r['tgid']==args.pid and args.threads)]
        if not rows: print('Process not found or inaccessible'); return
        for r in rows:
            for k,v in r.items(): print(f'{k:>20}: {v}')
            print()
    else: table(snapshot,args)

def main(argv=None):
    if not sys.platform.startswith('linux'): raise RuntimeError('Linux is required')
    p=parser_build(); args=p.parse_args(argv)
    if args.watch is not None: args.command='watch'; args.interval=args.watch
    if args.limit<1 or args.limit>100000: p.error('--limit must be between 1 and 100000')
    if args.interval<=0 or args.interval>3600: p.error('--interval must be within (0, 3600]')
    if args.count<0 or args.thread_limit<1 or args.max_scan<1 or args.depth<0 or args.cmd_length<8: p.error('invalid numeric option')
    if args.command=='diff' and not args.baseline: p.error('diff requires --baseline')
    if args.command=='inspect' and (args.pid is None or args.pid<1): p.error('inspect requires --pid')
    if not os.path.isdir(args.proc_root): raise RuntimeError(f'proc root unavailable: {args.proc_root}')
    collector=Collector(args.proc_root,args.threads,args.zombie,args.vm_size,args.max_scan,args.thread_limit,args.cmd_length,not args.no_io)
    if args.command=='watch':
        stopped=False
        def stop(sig,frame):
            nonlocal stopped
            stopped=True
        for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,stop)
        n=0
        history=collections.deque(maxlen=80)
        while not stopped and (args.count==0 or n<args.count):
            started=time.monotonic(); snapshot=collector.scan()
            history.append(snapshot['total_cpu']); args.history=history
            if args.format=='table' and sys.stdout.isatty(): print('\033[2J\033[H',end='')
            if args.command=='watch' and args.format=='table':
                original=args.command; args.command=args.view
                try: emit(snapshot,args)
                finally: args.command=original
            else: emit(snapshot,args)
            if args.output:
                if args.output.endswith('.csv'): export_csv(args.output,snapshot,append=True)
                else:
                    with open(args.output,'a',encoding='utf-8') as f: f.write(json.dumps(snapshot,ensure_ascii=False)+'\n')
            if args.svg: save_svg_art(args.svg,snapshot,args)
            if args.markdown: write_markdown_report(args.markdown,snapshot)
            n+=1
            if not stopped and (args.count==0 or n<args.count):
                wait=max(0,args.interval-(time.monotonic()-started))
                while wait>0 and not stopped:
                    sl=min(0.1,wait); time.sleep(sl); wait-=sl
        return 0
    snapshot=collector.scan()
    if args.svg: save_svg_art(args.svg,snapshot,args)
    if args.markdown: write_markdown_report(args.markdown,snapshot)
    if args.command=='diff': diff_snapshots(load_snapshot(args.baseline),snapshot,args)
    elif args.command in ('snapshot','baseline'):
        if args.output: atomic_json(args.output,snapshot); print(f'Saved snapshot: {args.output}',file=sys.stderr)
        else: print(json.dumps(snapshot,indent=2,ensure_ascii=False))
    else: emit(snapshot,args)
    if args.output and args.command not in ('snapshot','baseline'):
        if args.output.endswith('.csv'): export_csv(args.output,snapshot)
        else: atomic_json(args.output,snapshot)
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except (RuntimeError,OSError,ValueError) as e:
        print(f'procstat-python: {e}',file=sys.stderr); sys.exit(1)
