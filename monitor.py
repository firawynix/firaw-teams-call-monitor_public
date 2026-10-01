"""Monitor local de indícios de problemas durante chamadas do Teams."""

from __future__ import annotations

import csv
import ctypes
import datetime as dt
import ipaddress
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from collections import Counter
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from tkinter import messagebox, ttk

import psutil
from diagnostics import Check, fast_media_checks, run_diagnostics


ROOT = Path(__file__).resolve().parent


def package_family_name() -> str | None:
    """Return the MSIX family name, if this process has package identity."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_name = kernel32.GetCurrentPackageFamilyName
        get_name.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p]
        get_name.restype = ctypes.c_long
        length = ctypes.c_uint32(0)
        if get_name(ctypes.byref(length), None) != 122:  # ERROR_INSUFFICIENT_BUFFER
            return None
        buffer = ctypes.create_unicode_buffer(length.value)
        return buffer.value if get_name(ctypes.byref(length), buffer) == 0 else None
    except (AttributeError, OSError, ValueError):
        return None


LOCAL_DATA = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
PACKAGE_FAMILY = package_family_name()
if PACKAGE_FAMILY:
    DATA_DIR = LOCAL_DATA / "Packages" / PACKAGE_FAMILY / "LocalState" / "dados"
elif getattr(sys, "frozen", False):
    DATA_DIR = LOCAL_DATA / "TeamsCallMonitor" / "dados"
else:
    DATA_DIR = ROOT / "dados"
ICON_PATH = ROOT / "assets" / "icon-64.png"
INTERVAL = 2.0
TEAMS_HOST = "teams.microsoft.com"
BG = "#101827"
PANEL = "#1c293d"
TEXT = "#f2f5fa"
MUTED = "#aebbd0"
BLUE = "#61b5ff"
GREEN = "#65d9aa"
YELLOW = "#ffcc70"
RED = "#ff7c85"


@dataclass
class Sample:
    timestamp: str
    teams_open: bool
    teams_cpu: float
    system_cpu: float
    memory: float
    download_mbps: float
    upload_mbps: float
    teams_tcp_ms: float | None
    gateway_ms: float | None
    antivirus_cpu: float = 0.0
    top_processes: str = ""
    top_processes_fresh: bool = False


@dataclass
class DiagnosticBatch:
    timestamp: str
    checks: list[Check]
    partial: bool = False


@dataclass
class NetworkSnapshot:
    timestamp: str
    tcp: int
    udp: int
    tcp_bound: int
    tcp_time_wait: int
    top_tcp: str
    top_udp: str


def network_snapshot() -> NetworkSnapshot:
    """Count local sockets by owner; remote addresses are deliberately not logged."""
    tcp_owners: Counter[int] = Counter()
    udp_owners: Counter[int] = Counter()
    tcp = udp = tcp_bound = tcp_time_wait = 0
    for connection in psutil.net_connections(kind="inet"):
        if connection.type == socket.SOCK_STREAM:
            tcp += 1
            tcp_bound += connection.status == "BOUND"
            tcp_time_wait += connection.status == "TIME_WAIT"
            if connection.pid:
                tcp_owners[connection.pid] += 1
        elif connection.type == socket.SOCK_DGRAM:
            udp += 1
            if connection.pid:
                udp_owners[connection.pid] += 1

    names = {}
    for pid in set(tcp_owners) | set(udp_owners):
        try:
            names[pid] = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            names[pid] = "processo encerrado/restrito"

    def top(owners: Counter[int]) -> str:
        return "; ".join(f"{names[pid]} (PID {pid}): {count}"
                         for pid, count in owners.most_common(5))

    return NetworkSnapshot(dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                           tcp, udp, tcp_bound, tcp_time_wait,
                           top(tcp_owners), top(udp_owners))


def tcp_probe(host: str = TEAMS_HOST, port: int = 443, timeout: float = 1.2) -> float | None:
    """Connection setup time, not the media stream round-trip time."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.monotonic() - start) * 1000, 1)
    except OSError:
        return None


def default_gateway() -> str | None:
    if os.name != "nt":
        return None
    command = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.NextHop -ne '0.0.0.0' } | "
        "Sort-Object @{Expression={$_.RouteMetric + $_.InterfaceMetric}} | "
        "Select-Object -First 1 -ExpandProperty NextHop"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        value = result.stdout.strip().splitlines()[0].strip()
        ipaddress.IPv4Address(value)
        return value
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


class IcmpEchoReply(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_uint32), ("status", ctypes.c_uint32),
        ("round_trip_time", ctypes.c_uint32), ("data_size", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16), ("data", ctypes.c_void_p),
        ("options", ctypes.c_byte * 8),
    ]


def ping_ipv4(address: str | None, timeout_ms: int = 700) -> float | None:
    if not address or os.name != "nt":
        return None
    api = ctypes.WinDLL("iphlpapi.dll")
    api.IcmpCreateFile.restype = ctypes.c_void_p
    api.IcmpSendEcho.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint16,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
    ]
    api.IcmpSendEcho.restype = ctypes.c_uint32
    api.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    handle = api.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return None
    payload = ctypes.create_string_buffer(b"teams-monitor")
    response = ctypes.create_string_buffer(ctypes.sizeof(IcmpEchoReply) + 32)
    destination = int.from_bytes(socket.inet_aton(address), "little")
    try:
        count = api.IcmpSendEcho(
            handle, destination, payload, len(payload.value), None,
            response, len(response), timeout_ms,
        )
        if count:
            reply = IcmpEchoReply.from_buffer_copy(response)
            if reply.status == 0:
                return float(reply.round_trip_time)
        return None
    finally:
        api.IcmpCloseHandle(handle)


class ProcessSampler:
    """Cache process identities; scan every process's CPU during relevant load."""

    ANTIVIRUS_NAMES = {"msmpeng.exe", "bdservicehost.exe", "bdagent.exe", "avp.exe",
                       "avastsvc.exe", "avgsvc.exe", "sophosfs.exe"}

    def __init__(self):
        self.processes: dict[int, tuple[psutil.Process, str, int]] = {}
        self.family: set[int] = set()
        self.antivirus: set[int] = set()
        self.roots: set[int] = set()
        self.last_refresh = 0.0
        self.last_top = 0.0
        self.top_text = ""
        self.cpu_count = psutil.cpu_count() or 1

    def refresh(self):
        processes = {}
        children = {}
        roots = set()
        antivirus = set()
        for proc in psutil.process_iter(["name", "ppid"]):
            try:
                name = (proc.info["name"] or "").lower()
                parent = proc.info["ppid"]
                processes[proc.pid] = (proc, name, parent)
                if proc.pid not in self.processes:
                    # Prime the counter so the first busy-CPU scan has a baseline.
                    proc.cpu_percent(interval=None)
                children.setdefault(parent, []).append(proc.pid)
                if name in {"ms-teams.exe", "teams.exe"}:
                    roots.add(proc.pid)
                if name in self.ANTIVIRUS_NAMES:
                    antivirus.add(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        family = set(roots)
        pending = list(roots)
        while pending:
            for child in children.get(pending.pop(), []):
                if child not in family:
                    family.add(child)
                    pending.append(child)
        self.processes = processes
        self.roots = roots
        self.family = family
        self.antivirus = antivirus
        self.last_refresh = time.monotonic()

    def sample(self, system_cpu: float) -> tuple[bool, float, float, str, bool]:
        now = time.monotonic()
        if now - self.last_refresh >= 15:
            self.refresh()
        relevant_load = system_cpu >= 15
        scan_all = relevant_load and now - self.last_top >= 8
        pids = self.processes if scan_all else self.family | self.antivirus
        usage = {}
        for pid in pids:
            proc, name, _parent = self.processes[pid]
            try:
                usage[pid] = proc.cpu_percent(interval=None) / self.cpu_count
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        teams_cpu = sum(usage.get(pid, 0) for pid in self.family)
        antivirus_cpu = sum(usage.get(pid, 0) for pid in self.antivirus)
        if scan_all:
            groups: Counter[str] = Counter()
            for pid, cpu in usage.items():
                if pid and cpu >= 0.1:
                    groups[self.processes[pid][1] or "processo"] += cpu
            group_text = "; ".join(f"{name}: {cpu:.1f}%"
                                   for name, cpu in groups.most_common(5))
            top_pids = sorted(((cpu, pid, self.processes[pid][1]) for pid, cpu in usage.items()
                               if pid and cpu >= 0.1), reverse=True)[:3]
            pid_text = "; ".join(f"{name or 'processo'} (PID {pid}): {cpu:.1f}%"
                                 for cpu, pid, name in top_pids)
            self.top_text = (f"Programas: {group_text} | Processos: {pid_text}"
                             if groups else "Processos ainda sem medição válida")
            self.last_top = now
        elif not relevant_load:
            self.top_text = ""
            self.last_top = 0.0
        return (bool(self.roots), round(teams_cpu, 1),
                round(antivirus_cpu, 1), self.top_text, scan_all)


def assess(samples: list[Sample]) -> tuple[str, str]:
    """Return a cautious indication based only on recent local samples."""
    if not samples:
        return "Aguardando medições", MUTED
    recent = samples[-5:]
    if sum(s.teams_tcp_ms is None for s in recent) >= 2:
        return "Falhas de conexão com o serviço do Teams", RED
    if sum(s.gateway_ms is not None and s.gateway_ms > 50 for s in recent) >= 2:
        return "Resposta lenta da rede local", YELLOW
    if sum(s.teams_tcp_ms is not None and s.teams_tcp_ms > 250 for s in recent) >= 3:
        return "Conexão com o serviço do Teams lenta", YELLOW
    if sum(s.system_cpu >= 85 for s in recent) >= 3:
        return "CPU do computador muito ocupada", YELLOW
    if sum(s.memory >= 90 for s in recent) >= 3:
        return "Memória do computador quase cheia", YELLOW
    if sum(s.antivirus_cpu >= 15 and s.system_cpu >= 70 for s in recent) >= 3:
        return "CPU alta junto de atividade do antivírus (correlação)", YELLOW
    return "Sem alerta nas medições locais", GREEN


def live_checks(samples: list[Sample], in_call: bool = False) -> list[Check]:
    if not samples:
        return []
    recent = samples[-5:]
    latest = recent[-1]
    checks = []

    failures = sum(s.teams_tcp_ms is None for s in recent)
    latencies = [s.teams_tcp_ms for s in recent if s.teams_tcp_ms is not None]
    slow = sum(ms > 250 for ms in latencies)
    very_slow = sum(ms > 500 for ms in latencies)
    network_state = ("error" if failures >= 2 or very_slow >= 3 else
                     "warning" if failures or slow >= 2 else "ok")
    checks.append(Check("live_teams", "Conexão com Teams · agora", network_state,
                        f"Últimas {len(recent)} sondas: {failures} falha(s); "
                        + (f"última conexão {latest.teams_tcp_ms:.0f} ms." if latest.teams_tcp_ms is not None
                           else "última conexão falhou."),
                        "Sonda TCP de acesso ao serviço; não é a perda de pacotes da chamada."))

    gateway_ok = [s.gateway_ms for s in recent if s.gateway_ms is not None]
    if not gateway_ok:
        gateway_state = "info"
        gateway_detail = "Gateway sem resposta a ICMP; este teste não permite concluir que há falha."
    else:
        missed = len(recent) - len(gateway_ok)
        gateway_state = ("error" if missed >= 2 or sum(ms > 100 for ms in gateway_ok) >= 2 else
                         "warning" if missed or sum(ms > 50 for ms in gateway_ok) >= 2 else "ok")
        gateway_detail = f"Últimas {len(recent)} sondas: {missed} sem resposta; última {gateway_ok[-1]:.0f} ms."
    checks.append(Check("live_gateway", "Rede local · gateway", gateway_state, gateway_detail,
                        "Verifique cabo, Wi-Fi, roteador e uso intenso da rede se houver instabilidade."))

    cpu_high = sum(s.system_cpu >= 85 for s in recent)
    cpu_critical = sum(s.system_cpu >= 95 for s in recent)
    cpu_detail = f"Agora {latest.system_cpu:.0f}%; {cpu_high}/{len(recent)} amostras acima de 85%."
    if latest.system_cpu >= 15 and latest.top_processes:
        cpu_detail += " Maiores processos: " + latest.top_processes
    checks.append(Check("live_cpu", "CPU do computador", "error" if cpu_critical >= 3 else
                        "warning" if cpu_high >= 3 else "ok",
                        cpu_detail))

    memory_high = sum(s.memory >= 90 for s in recent)
    memory_critical = sum(s.memory >= 95 for s in recent)
    checks.append(Check("live_memory", "Memória do computador", "error" if memory_critical >= 3 else
                        "warning" if memory_high >= 3 else "ok",
                        f"Agora {latest.memory:.0f}%; {memory_high}/{len(recent)} amostras acima de 90%."))

    if latest.teams_open:
        busy = sum(s.teams_cpu >= 25 for s in recent)
        critical = sum(s.teams_cpu >= 50 for s in recent)
        teams_state = "error" if critical >= 3 else "warning" if busy >= 3 else "ok"
        teams_detail = f"Teams e processos filhos: {latest.teams_cpu:.0f}% da CPU total."
    else:
        teams_state = "error" if in_call else "info"
        teams_detail = ("Teams de desktop deixou de ser detectado durante a ligação marcada."
                        if in_call else "Aplicativo de desktop do Teams não detectado.")
    checks.append(Check("live_teams_cpu", "Carga do aplicativo Teams", teams_state, teams_detail,
                        "O Teams no navegador não é identificado por este indicador."))

    antivirus_busy = sum(s.antivirus_cpu >= 15 and s.system_cpu >= 70 for s in recent)
    antivirus_state = "warning" if antivirus_busy >= 3 else "ok"
    checks.append(Check("live_antivirus_cpu", "Carga simultânea do antivírus", antivirus_state,
                        f"Processos reconhecidos: {latest.antivirus_cpu:.0f}% da CPU total; "
                        f"{antivirus_busy}/{len(recent)} amostras com PC ocupado.",
                        "É apenas correlação de uso de CPU; não atribui a falha ao antivírus."))
    return checks


class MonitorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Monitor de chamadas do Teams")
        if ICON_PATH.is_file():
            try:
                self.icon = tk.PhotoImage(file=str(ICON_PATH))
                self.root.iconphoto(True, self.icon)
            except tk.TclError:
                self.icon = None
        self.root.geometry("900x750")
        self.root.minsize(780, 650)
        self.root.configure(bg=BG)
        self.samples: deque[Sample] = deque(maxlen=180)
        self.call_samples: list[Sample] = []
        self.inbox: queue.Queue[Sample | DiagnosticBatch | NetworkSnapshot | Exception] = queue.Queue()
        self.stop_event = threading.Event()
        self.call_started: dt.datetime | None = None
        self.presenting = False
        self.writer = None
        self.csv_file = None
        self.csv_path: Path | None = None
        self.events: list[tuple[str, str, str]] = []
        self.checks: list[Check] = []
        self.live_checks: list[Check] = []
        self.previous_checks: dict[str, Check] = {}
        self.previous_live_checks: dict[str, Check] = {}
        self.visible_checks: list[Check] = []
        self.previous_alert = ""
        self.last_teams_open: bool | None = None
        self.details_window: tk.Toplevel | None = None
        self.gateway = None
        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.worker = threading.Thread(target=self.measure_loop, daemon=True)
        self.worker.start()
        self.diagnostic_worker = threading.Thread(target=self.diagnostic_loop, daemon=True)
        self.diagnostic_worker.start()
        self.fast_worker = threading.Thread(target=self.fast_media_loop, daemon=True)
        self.fast_worker.start()
        self.network_worker = threading.Thread(target=self.network_loop, daemon=True)
        self.network_worker.start()
        self.root.after(250, self.consume)

    def label(self, parent, text, size=11, color=TEXT, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", BG), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"),
                        **kwargs)

    def build_ui(self):
        main = tk.Frame(self.root, bg=BG, padx=24, pady=20)
        main.pack(fill="both", expand=True)
        self.label(main, "Monitor de chamadas do Teams", 21, bold=True).pack(anchor="w")
        self.label(main, "Acompanhe a rede e o computador durante ligações e apresentações.",
                   10, MUTED).pack(anchor="w", pady=(3, 16))

        status = tk.Frame(main, bg=PANEL, padx=16, pady=12)
        status.pack(fill="x")
        self.call_label = self.label(status, "● Fora de chamada", 12, MUTED, True, bg=PANEL)
        self.call_label.pack(side="left")
        self.teams_label = self.label(status, "Teams: verificando...", 10, MUTED, bg=PANEL)
        self.teams_label.pack(side="right")

        health = tk.Frame(main, bg=PANEL, padx=16, pady=9)
        health.pack(fill="x", pady=(9, 0))
        self.health_label = self.label(health, "CINZA · Aguardando diagnóstico", 12, MUTED, True, bg=PANEL)
        self.health_label.pack(side="left")
        self.health_counts = self.label(health, "", 9, MUTED, bg=PANEL)
        self.health_counts.pack(side="right")

        buttons = tk.Frame(main, bg=BG)
        buttons.pack(fill="x", pady=13)
        self.call_button = self.button(buttons, "Marcar início da ligação", self.toggle_call, BLUE)
        self.call_button.pack(side="left", padx=(0, 8))
        self.present_button = self.button(buttons, "Marcar apresentação", self.toggle_presentation, PANEL)
        self.present_button.pack(side="left", padx=(0, 8))
        self.stutter_button = self.button(buttons, "Marcar engasgo", self.mark_stutter, YELLOW)
        self.stutter_button.pack(side="left")
        self.button(buttons, "Ver componentes", self.show_diagnostics, PANEL).pack(side="right")
        self.present_button.configure(state="disabled")
        self.stutter_button.configure(state="disabled")
        self.label(main, "Esses botões só marcam horários no relatório; não controlam o Teams.",
                   9, MUTED).pack(anchor="w", pady=(0, 4))

        cards = tk.Frame(main, bg=BG)
        cards.pack(fill="x", pady=(3, 10))
        self.values = {}
        for index, (key, title) in enumerate([
            ("teams_tcp", "CONEXÃO COM TEAMS"),
            ("gateway", "REDE LOCAL"),
            ("cpu", "CPU DO PC"),
            ("memory", "MEMÓRIA"),
        ]):
            card = tk.Frame(cards, bg=PANEL, padx=13, pady=10)
            card.grid(row=0, column=index, sticky="nsew", padx=(0, 8 if index < 3 else 0))
            cards.grid_columnconfigure(index, weight=1)
            self.label(card, title, 8, MUTED, True, bg=PANEL).pack(anchor="w")
            value = self.label(card, "—", 20, TEXT, True, bg=PANEL)
            value.pack(anchor="w", pady=(3, 0))
            self.values[key] = value

        self.traffic_label = self.label(main, "Tráfego total: aguardando...", 10, MUTED)
        self.traffic_label.pack(anchor="w", pady=(0, 10))
        self.label(main, "Tempo de conexão com Teams (últimos 6 minutos)", 11, bold=True).pack(anchor="w")
        self.graph = tk.Canvas(main, height=155, bg=PANEL, highlightthickness=0)
        self.graph.pack(fill="x", pady=(6, 12))
        self.graph.bind("<Configure>", lambda _event: self.draw_graph())

        alert_frame = tk.Frame(main, bg=PANEL, padx=14, pady=12)
        alert_frame.pack(fill="x")
        self.alert_label = self.label(alert_frame, "Aguardando medições", 11, MUTED, True, bg=PANEL)
        self.alert_label.pack(anchor="w")
        self.label(alert_frame, "Sondas de rede e uso do PC; não são métricas internas da chamada.",
                   9, MUTED, bg=PANEL).pack(anchor="w", pady=(3, 0))

        self.event_label = self.label(main, "Nenhum engasgo marcado nesta chamada.", 10, MUTED)
        self.event_label.pack(anchor="w", pady=(12, 4))
        self.file_label = self.label(main, "Os relatórios serão salvos em: " + str(DATA_DIR), 9, MUTED,
                                     wraplength=740, justify="left")
        self.file_label.pack(anchor="w")
        self.label(main, "Durante uma ligação, no Teams: Mais ações (⋯) → Configurações → Integridade da chamada.",
                   9, MUTED, wraplength=740, justify="left").pack(anchor="w", pady=(10, 0))

    def button(self, parent, text, command, color):
        return tk.Button(parent, text=text, command=command, bg=color,
                         fg="#101827" if color != PANEL else TEXT,
                         activebackground=color, activeforeground="#101827",
                         font=("Segoe UI", 10, "bold"), relief="flat",
                         padx=13, pady=9, cursor="hand2")

    def measure_loop(self):
        try:
            self.gateway = default_gateway()
            psutil.cpu_percent(interval=None)
            process_sampler = ProcessSampler()
            previous = psutil.net_io_counters()
            previous_time = time.monotonic()
            while not self.stop_event.is_set():
                started = time.monotonic()
                try:
                    cpu = psutil.cpu_percent(interval=None)
                    (teams_open, teams_cpu, antivirus_cpu,
                     top_processes, top_processes_fresh) = process_sampler.sample(cpu)
                    memory = psutil.virtual_memory().percent
                    current = psutil.net_io_counters()
                    elapsed = started - previous_time
                    if elapsed < 1:
                        download = upload = 0.0
                    else:
                        download = max(0, current.bytes_recv - previous.bytes_recv) * 8 / elapsed / 1_000_000
                        upload = max(0, current.bytes_sent - previous.bytes_sent) * 8 / elapsed / 1_000_000
                    previous, previous_time = current, started
                    tcp_ms = tcp_probe()
                    gateway_ms = ping_ipv4(self.gateway)
                    self.inbox.put(Sample(
                        dt.datetime.now().astimezone().isoformat(timespec="seconds"), teams_open,
                        teams_cpu, round(cpu, 1), round(memory, 1),
                        round(download, 2), round(upload, 2), tcp_ms, gateway_ms,
                        antivirus_cpu, top_processes, top_processes_fresh,
                    ))
                except Exception as exc:
                    self.inbox.put(exc)
                self.stop_event.wait(max(0, INTERVAL - (time.monotonic() - started)))
        except Exception as exc:
            self.inbox.put(exc)

    def diagnostic_loop(self):
        while not self.stop_event.is_set():
            try:
                self.inbox.put(DiagnosticBatch(
                    dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                    run_diagnostics(),
                ))
            except Exception as exc:
                self.inbox.put(exc)
            self.stop_event.wait(60)

    def fast_media_loop(self):
        self.stop_event.wait(5)
        while not self.stop_event.is_set():
            try:
                self.inbox.put(DiagnosticBatch(
                    dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                    fast_media_checks(), partial=True,
                ))
            except Exception as exc:
                self.inbox.put(exc)
            self.stop_event.wait(10)

    def network_loop(self):
        while not self.stop_event.is_set():
            try:
                self.inbox.put(network_snapshot())
            except Exception as exc:
                self.inbox.put(exc)
            self.stop_event.wait(30)

    def append_csv(self, name: str, header: list[str], row: list):
        DATA_DIR.mkdir(exist_ok=True)
        date = dt.datetime.now().astimezone().strftime("%Y%m%d")
        path = DATA_DIR / f"{name}_{date}.csv"
        is_new = not path.exists()
        with path.open("a", newline="", encoding="utf-8-sig") as file:
            writer = csv.writer(file)
            if is_new:
                writer.writerow(header)
            writer.writerow(row)

    def log_occurrence(self, component: str, level: str, description: str, evidence: str = ""):
        self.append_csv("ocorrencias", ["horario", "componente", "nivel", "descricao", "evidencia"],
                        [dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                         component, level, description, evidence])

    def record_diagnostics(self, batch: DiagnosticBatch):
        if batch.partial:
            merged = {check.key: check for check in self.checks}
            merged.update({check.key: check for check in batch.checks})
            self.checks = list(merged.values())
        else:
            self.checks = batch.checks
        DATA_DIR.mkdir(exist_ok=True)
        path = DATA_DIR / f"componentes_{dt.datetime.now().astimezone():%Y%m%d}.jsonl"
        with path.open("a", encoding="utf-8") as file:
            file.write(json.dumps({"horario": batch.timestamp,
                                   "tipo": "rápida" if batch.partial else "completa",
                                   "verificacoes": [check.as_dict() for check in batch.checks]},
                                  ensure_ascii=False) + "\n")
        for check in batch.checks:
            previous = self.previous_checks.get(check.key)
            changed = previous and previous.detail != check.detail
            if changed and check.key == "teams_webview":
                # Family memory naturally varies every few seconds; log process-count changes.
                changed = previous.detail.split(";", 1)[0] != check.detail.split(";", 1)[0]
            if check.state in {"warning", "error"} and (not previous or previous.state != check.state):
                self.log_occurrence(check.component, check.state, check.detail, check.action)
            elif (changed and check.key in {"whea_recent", "port_exhaustion", "dns_timeout_event"}
                  and check.state in {"warning", "error"}):
                # Log each newly observed system event even if its color stays yellow.
                marker = "mais recente: " if check.key == "whea_recent" else "última em "
                old_latest = previous.detail.rsplit(marker, 1)[-1]
                new_latest = check.detail.rsplit(marker, 1)[-1]
                if old_latest != new_latest:
                    self.log_occurrence(check.component, check.state, check.detail, check.action)
            elif previous and previous.state in {"warning", "error"} and check.state == "ok":
                self.log_occurrence(check.component, "recovery", "Condição normalizada: " + check.detail)
            elif changed and check.key in {"audio_microphone", "audio_speaker", "camera_device",
                                                "adapter", "privacy_microphone", "privacy_webcam",
                                                "teams_mixer", "teams_webview"}:
                self.log_occurrence(check.component, "change", "Estado mudou: " + check.detail)
            self.previous_checks[check.key] = check
        self.update_health()
        self.refresh_diagnostics()

    def consume(self):
        try:
            while True:
                item = self.inbox.get_nowait()
                if isinstance(item, Exception):
                    self.alert_label.configure(text=f"Erro de medição: {item}", fg=RED)
                    self.log_occurrence("Monitor", "error", f"Erro de medição: {item}")
                    continue
                if isinstance(item, DiagnosticBatch):
                    self.record_diagnostics(item)
                    continue
                if isinstance(item, NetworkSnapshot):
                    self.append_csv("portas_rede", ["horario", "tcp", "udp", "tcp_bound",
                                                    "tcp_time_wait", "maiores_tcp", "maiores_udp"],
                                    [item.timestamp, item.tcp, item.udp, item.tcp_bound,
                                     item.tcp_time_wait, item.top_tcp, item.top_udp])
                    continue
                self.samples.append(item)
                self.update_view(item)
                self.append_csv("amostras", [
                    "horario", "em_chamada", "apresentando", "teams_aberto", "teams_cpu_pct",
                    "cpu_pc_pct", "memoria_pct", "antivirus_cpu_pct", "download_mbps",
                    "upload_mbps", "conexao_teams_ms", "gateway_ms",
                ], [
                    item.timestamp, int(bool(self.call_started)), int(self.presenting),
                    int(item.teams_open), item.teams_cpu, item.system_cpu, item.memory,
                    item.antivirus_cpu, item.download_mbps, item.upload_mbps,
                    item.teams_tcp_ms if item.teams_tcp_ms is not None else "",
                    item.gateway_ms if item.gateway_ms is not None else "",
                ])
                if item.top_processes_fresh and item.system_cpu >= 85:
                    self.append_csv("processos_cpu_alta", ["horario", "cpu_pc_pct", "maiores_processos"],
                                    [item.timestamp, item.system_cpu, item.top_processes])
                elif item.top_processes_fresh and item.system_cpu >= 15:
                    self.append_csv("processos_cpu_moderada",
                                    ["horario", "cpu_pc_pct", "maiores_processos"],
                                    [item.timestamp, item.system_cpu, item.top_processes])
                if self.writer:
                    self.call_samples.append(item)
                    self.writer.writerow([
                        item.timestamp, "sim" if self.presenting else "não",
                        int(item.teams_open), item.teams_cpu, item.system_cpu, item.memory,
                        item.download_mbps, item.upload_mbps,
                        item.teams_tcp_ms if item.teams_tcp_ms is not None else "",
                        item.gateway_ms if item.gateway_ms is not None else "",
                        item.antivirus_cpu,
                    ])
                    self.csv_file.flush()
        except queue.Empty:
            pass
        self.root.after(250, self.consume)

    def update_view(self, sample: Sample):
        self.values["teams_tcp"].configure(
            text=f"{sample.teams_tcp_ms:.0f} ms" if sample.teams_tcp_ms is not None else "Falhou",
            fg=RED if sample.teams_tcp_ms is None else TEXT,
        )
        self.values["gateway"].configure(
            text=f"{sample.gateway_ms:.0f} ms" if sample.gateway_ms is not None else "Sem resposta")
        self.values["cpu"].configure(text=f"{sample.system_cpu:.0f}%")
        self.values["memory"].configure(text=f"{sample.memory:.0f}%")
        self.teams_label.configure(text=f"Teams: {'aberto' if sample.teams_open else 'não detectado'}"
                                        + (f" · CPU {sample.teams_cpu:.0f}%" if sample.teams_open else ""))
        if self.call_started and self.last_teams_open and not sample.teams_open:
            self.log_occurrence("Aplicativo Teams", "error",
                                "Teams de desktop deixou de ser detectado durante a ligação marcada.")
        self.last_teams_open = sample.teams_open
        self.traffic_label.configure(text=f"Tráfego total: ↓ {sample.download_mbps:.2f} Mb/s  "
                                          f"↑ {sample.upload_mbps:.2f} Mb/s")
        alert, color = assess(list(self.samples))
        self.alert_label.configure(text=alert, fg=color)
        if alert != self.previous_alert:
            if color in {RED, YELLOW}:
                self.log_occurrence("Rede ou computador", "error" if color == RED else "warning", alert,
                                    f"Teams TCP={sample.teams_tcp_ms} ms; gateway={sample.gateway_ms} ms; "
                                    f"CPU={sample.system_cpu}%; antivírus CPU={sample.antivirus_cpu}%")
            elif self.previous_alert and self.previous_alert != "Sem alerta nas medições locais":
                self.log_occurrence("Rede ou computador", "recovery", "Medições locais normalizadas")
            self.previous_alert = alert
        self.live_checks = live_checks(list(self.samples), in_call=bool(self.call_started))
        for check in self.live_checks:
            previous = self.previous_live_checks.get(check.key)
            if check.state in {"warning", "error"} and (not previous or previous.state != check.state):
                self.log_occurrence(check.component, check.state, check.detail, check.action)
            elif previous and previous.state in {"warning", "error"} and check.state == "ok":
                self.log_occurrence(check.component, "recovery", "Condição normalizada: " + check.detail)
            self.previous_live_checks[check.key] = check
        self.update_health()
        self.refresh_diagnostics()
        self.draw_graph()

    def update_health(self):
        all_checks = self.live_checks + self.checks
        red = sum(check.state == "error" for check in all_checks)
        yellow = sum(check.state == "warning" for check in all_checks)
        green = sum(check.state == "ok" for check in all_checks)
        grey = sum(check.state == "info" for check in all_checks)
        if red:
            label, color = "VERMELHO · Há falhas para verificar", RED
        elif yellow:
            label, color = "AMARELO · Há itens que pedem atenção", YELLOW
        elif green:
            label, color = "VERDE · Verificações normais", GREEN
        else:
            label, color = "CINZA · Aguardando diagnóstico", MUTED
        self.health_label.configure(text=label, fg=color)
        self.health_counts.configure(text=f"{green} verdes  ·  {yellow} amarelos  ·  {red} vermelhos"
                                          + (f"  ·  {grey} informativos" if grey else ""))

    def draw_graph(self):
        self.graph.delete("all")
        width = max(self.graph.winfo_width(), 100)
        height = max(self.graph.winfo_height(), 100)
        pad = 15
        for limit in (50, 150, 250):
            y = height - pad - min(limit / 300, 1) * (height - 2 * pad)
            self.graph.create_line(pad, y, width - pad, y, fill="#30445d", dash=(3, 5))
            self.graph.create_text(width - pad - 4, y - 8, text=f"{limit} ms", anchor="e",
                                   fill=MUTED, font=("Segoe UI", 8))
        values = list(self.samples)[-180:]
        if len(values) < 2:
            return
        coords = []
        for i, sample in enumerate(values):
            x = pad + i / 179 * (width - 2 * pad)
            if sample.teams_tcp_ms is None:
                if len(coords) >= 4:
                    self.graph.create_line(*coords, fill=BLUE, width=2, smooth=True)
                coords = []
                self.graph.create_oval(x - 3, height - pad - 3, x + 3, height - pad + 3,
                                       fill=RED, outline="")
            else:
                y = height - pad - min(sample.teams_tcp_ms / 300, 1) * (height - 2 * pad)
                coords.extend((x, y))
        if len(coords) >= 4:
            self.graph.create_line(*coords, fill=BLUE, width=2, smooth=True)

    def show_diagnostics(self):
        if self.details_window and self.details_window.winfo_exists():
            self.details_window.lift()
            return
        window = tk.Toplevel(self.root)
        self.details_window = window
        window.title("Componentes do Teams e do Windows")
        window.geometry("820x590")
        window.configure(bg=BG)
        frame = tk.Frame(window, bg=BG, padx=20, pady=18)
        frame.pack(fill="both", expand=True)
        self.label(frame, "Diagnóstico por componente", 18, bold=True).pack(anchor="w")
        self.label(frame, "Áudio e processos a cada 10 s; demais testes a cada minuto. Selecione um item.",
                   10, MUTED).pack(anchor="w", pady=(4, 12))
        self.label(frame, "VERDE: OK     AMARELO: atenção     VERMELHO: ruim     CINZA: informativo",
                   10, MUTED).pack(anchor="w", pady=(0, 9))
        self.detail_list = tk.Listbox(frame, bg=PANEL, fg=TEXT, selectbackground="#315982",
                                      selectforeground=TEXT, relief="flat", height=14,
                                      font=("Segoe UI", 10), activestyle="none")
        self.detail_list.pack(fill="both", expand=True)
        self.detail_list.bind("<<ListboxSelect>>", self.show_selected_check)
        self.detail_text = tk.Text(frame, bg=PANEL, fg=TEXT, wrap="word", relief="flat",
                                   height=7, padx=12, pady=10, font=("Segoe UI", 10))
        self.detail_text.pack(fill="x", pady=(10, 8))
        self.detail_text.configure(state="disabled")
        controls = tk.Frame(frame, bg=BG)
        controls.pack(fill="x")
        self.button(controls, "Atualizar agora", self.request_diagnostics, BLUE).pack(side="left")
        self.button(controls, "Teste oficial de mídia UDP", self.open_microsoft_test, PANEL).pack(side="left", padx=8)
        self.button(controls, "Abrir logs", self.open_logs, PANEL).pack(side="right")
        self.refresh_diagnostics()

    def refresh_diagnostics(self):
        if not self.details_window or not self.details_window.winfo_exists():
            return
        selected_key = None
        if self.visible_checks and self.detail_list.curselection():
            selected_key = self.visible_checks[self.detail_list.curselection()[0]].key
        scroll = self.detail_list.yview()[0]
        self.detail_list.delete(0, "end")
        self.visible_checks = sorted(self.live_checks + self.checks,
                                     key=lambda check: ({"error": 0, "warning": 1,
                                                         "ok": 2, "info": 3}.get(check.state, 4),
                                                        check.component.lower()))
        if not self.visible_checks:
            self.detail_list.insert("end", "Aguardando a primeira verificação...")
            return
        markers = {"ok": "VERDE · OK", "info": "CINZA · INFO", "warning": "AMARELO · MÉDIO",
                   "error": "VERMELHO · RUIM"}
        colors = {"ok": GREEN, "info": MUTED, "warning": YELLOW, "error": RED}
        for index, check in enumerate(self.visible_checks):
            preview = check.detail[:72] + ("…" if len(check.detail) > 72 else "")
            self.detail_list.insert("end", f"[{markers.get(check.state, '?')}]  {check.component} — {preview}")
            self.detail_list.itemconfig(index, foreground=colors.get(check.state, MUTED))
        selected_index = next((index for index, check in enumerate(self.visible_checks)
                               if check.key == selected_key), 0)
        self.detail_list.selection_set(selected_index)
        self.detail_list.yview_moveto(scroll)
        self.show_selected_check()

    def show_selected_check(self, _event=None):
        if not self.visible_checks or not self.detail_list.curselection():
            return
        check = self.visible_checks[self.detail_list.curselection()[0]]
        text = f"{check.component}\n\n{check.detail}"
        if check.action:
            text += f"\n\nO que conferir: {check.action}"
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    def request_diagnostics(self):
        def run():
            try:
                self.inbox.put(DiagnosticBatch(
                    dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                    run_diagnostics(),
                ))
            except Exception as exc:
                self.inbox.put(exc)
        threading.Thread(target=run, daemon=True).start()

    def open_logs(self):
        DATA_DIR.mkdir(exist_ok=True)
        os.startfile(DATA_DIR)

    def open_microsoft_test(self):
        webbrowser.open("https://connectivity.m365.cloud.microsoft/")

    def toggle_call(self):
        if self.call_started:
            self.end_call()
        else:
            DATA_DIR.mkdir(exist_ok=True)
            self.call_started = dt.datetime.now().astimezone()
            self.events = []
            self.call_samples = []
            self.presenting = False
            self.csv_path = DATA_DIR / f"chamada_{self.call_started:%Y%m%d_%H%M%S}.csv"
            self.csv_file = self.csv_path.open("w", newline="", encoding="utf-8-sig")
            self.writer = csv.writer(self.csv_file)
            self.writer.writerow([
                "horario", "apresentando", "teams_aberto", "teams_cpu_pct",
                "cpu_pc_pct", "memoria_pct", "download_mbps", "upload_mbps",
                "conexao_teams_ms", "gateway_ms", "antivirus_cpu_pct",
            ])
            self.csv_file.flush()
            self.call_button.configure(text="Encerrar e gerar relatório", bg=RED, activebackground=RED)
            self.present_button.configure(state="normal")
            self.stutter_button.configure(state="normal")
            self.call_label.configure(text="● Chamada em andamento", fg=GREEN)
            self.event_label.configure(text="Nenhum engasgo marcado nesta chamada.")

    def toggle_presentation(self):
        if not self.call_started:
            return
        self.presenting = not self.presenting
        action = "Início da apresentação" if self.presenting else "Fim da apresentação"
        self.record_event(action)
        self.present_button.configure(text="Marcar fim da apresentação" if self.presenting else "Marcar apresentação",
                                      bg=GREEN if self.presenting else PANEL,
                                      fg="#101827" if self.presenting else TEXT,
                                      activebackground=GREEN if self.presenting else PANEL)
        self.call_label.configure(text="● Chamada + apresentação" if self.presenting else "● Chamada em andamento")

    def mark_stutter(self):
        if not self.call_started:
            return
        alert, _color = assess(list(self.samples))
        detail = alert if alert != "Sem alerta nas medições locais" else "Sem indício claro nas medições locais"
        issues = [check.component + ": " + check.detail for check in self.live_checks + self.checks
                  if check.state in {"warning", "error"}]
        if issues:
            detail += "; componentes: " + " | ".join(issues)
        self.record_event("Engasgo percebido", detail)
        self.log_occurrence("Áudio percebido", "reported", "Engasgo marcado pelo usuário", detail)
        count = sum(kind == "Engasgo percebido" for _, kind, _ in self.events)
        self.event_label.configure(text=f"Engasgos marcados nesta chamada: {count}. Último: {detail}.")

    def record_event(self, kind: str, detail: str = ""):
        stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
        self.events.append((stamp, kind, detail))
        if self.csv_path:
            path = self.csv_path.with_name(self.csv_path.stem + "_eventos.csv")
            new = not path.exists()
            with path.open("a", newline="", encoding="utf-8-sig") as file:
                writer = csv.writer(file)
                if new:
                    writer.writerow(["horario", "evento", "observacao"])
                writer.writerow([stamp, kind, detail])

    def end_call(self):
        if self.presenting:
            self.toggle_presentation()
        ended = dt.datetime.now().astimezone()
        start = self.call_started
        self.call_started = None
        if self.csv_file:
            self.csv_file.close()
        self.writer = self.csv_file = None
        self.call_button.configure(text="Marcar início da ligação", bg=BLUE, activebackground=BLUE)
        self.present_button.configure(text="Marcar apresentação", state="disabled", bg=PANEL, fg=TEXT)
        self.stutter_button.configure(state="disabled")
        self.call_label.configure(text="● Fora de chamada", fg=MUTED)
        if start and self.csv_path:
            summary = self.csv_path.with_name(self.csv_path.stem + "_resumo.txt")
            stutters = sum(kind == "Engasgo percebido" for _, kind, _ in self.events)
            with summary.open("w", encoding="utf-8") as file:
                file.write("RESUMO DA CHAMADA\n")
                file.write(f"Início: {start:%d/%m/%Y %H:%M:%S}\n")
                file.write(f"Fim: {ended:%d/%m/%Y %H:%M:%S}\n")
                file.write(f"Duração: {str(ended - start).split('.')[0]}\n")
                file.write(f"Engasgos marcados: {stutters}\n")
                file.write(f"Amostras: {self.csv_path.name}\n\n")
                tcp_values = sorted(s.teams_tcp_ms for s in self.call_samples
                                    if s.teams_tcp_ms is not None)
                tcp_failures = sum(s.teams_tcp_ms is None for s in self.call_samples)
                gateway_values = [s.gateway_ms for s in self.call_samples
                                  if s.gateway_ms is not None]
                file.write("MEDIÇÕES LOCAIS\n")
                file.write(f"Amostras coletadas: {len(self.call_samples)}\n")
                file.write(f"Falhas de conexão com Teams: {tcp_failures}\n")
                if tcp_values:
                    p95 = tcp_values[min(len(tcp_values) - 1, int(0.95 * len(tcp_values)))]
                    file.write(f"Tempo de conexão mediano: {tcp_values[len(tcp_values) // 2]:.1f} ms\n")
                    file.write(f"Tempo de conexão p95: {p95:.1f} ms\n")
                if gateway_values:
                    file.write(f"Respostas do gateway acima de 50 ms: "
                               f"{sum(value > 50 for value in gateway_values)}\n")
                file.write(f"Amostras com CPU acima de 85%: "
                           f"{sum(s.system_cpu >= 85 for s in self.call_samples)}\n")
                file.write(f"Amostras com memória acima de 90%: "
                           f"{sum(s.memory >= 90 for s in self.call_samples)}\n\n")
                file.write(f"Amostras com antivírus usando 15% ou mais de CPU: "
                           f"{sum(s.antivirus_cpu >= 15 for s in self.call_samples)}\n\n")
                file.write("ÚLTIMA VERIFICAÇÃO DOS COMPONENTES\n")
                colors = {"ok": "VERDE", "warning": "AMARELO", "error": "VERMELHO", "info": "CINZA"}
                for check in self.live_checks + self.checks:
                    file.write(f"{check.component}: {colors.get(check.state, check.state)} — "
                               f"{check.detail}\n")
                file.write("\n")
                file.write("EVENTOS\n")
                for stamp, kind, detail in self.events:
                    file.write(f"{stamp} | {kind}" + (f" | {detail}" if detail else "") + "\n")
                file.write("\nAs sondas são indicadores locais e não medem diretamente o áudio do Teams.\n")
            self.file_label.configure(text=f"Relatório salvo: {summary}")
            messagebox.showinfo("Chamada encerrada", f"Relatório salvo em:\n{summary}")

    def on_close(self):
        if self.call_started:
            self.end_call()
        self.stop_event.set()
        self.root.destroy()


if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit("Este programa foi feito para Windows.")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    mutex = kernel32.CreateMutexW(None, False, "Local\\TeamsCallMonitorSingleton")
    if not mutex:
        raise SystemExit("Não foi possível iniciar a instância única do monitor.")
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(mutex)
        raise SystemExit(0)
    try:
        app_root = tk.Tk()
        MonitorApp(app_root)
        app_root.mainloop()
    finally:
        kernel32.CloseHandle(mutex)
