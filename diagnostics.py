"""Read-only Windows checks that complement the live connection samples."""

from __future__ import annotations

import json
import os
import random
import socket
import ssl
import struct
import subprocess
import time
import winreg
from collections import deque
from dataclasses import asdict, dataclass

import psutil


_last_adapter_errors: dict[str, int] = {}
_dns_history: dict[str, deque[tuple[str, float | None]]] = {}
_dns_round = 0


@dataclass
class Check:
    key: str
    component: str
    state: str  # ok, warning, error, info
    detail: str
    action: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def endpoint_checks(key: str, component: str, host: str) -> list[Check]:
    dns_start = time.monotonic()
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        return [
            Check(key + "_dns", "Resolução local · " + component, "error",
                  f"Resolução de {host} falhou: {exc}.",
                  "Verifique o DNS da rede e o proxy da empresa."),
            Check(key + "_tcp", "Conexão · " + component, "info",
                  "Não testada porque o DNS não respondeu."),
        ]
    dns_ms = (time.monotonic() - dns_start) * 1000
    dns = Check(key + "_dns", "Resolução local · " + component,
                "warning" if dns_ms > 300 else "ok",
                f"Consulta pelo Windows para {host}: {dns_ms:.0f} ms "
                "(inclui cache e processamento local; amarelo acima de 300 ms).",
                "Compare com o teste direto do servidor DNS; um pico isolado não prova lentidão do servidor.")
    error = None
    for family, sock_type, protocol, _canon, address in addresses:
        start = time.monotonic()
        try:
            with socket.socket(family, sock_type, protocol) as connection:
                connection.settimeout(1.5)
                connection.connect(address)
            connect_ms = (time.monotonic() - start) * 1000
            return [dns, Check(key + "_tcp", "Conexão · " + component,
                               "warning" if connect_ms > 300 else "ok",
                               f"Conexão TCP direta com {host} ({address[0]}): {connect_ms:.0f} ms "
                               "(amarelo acima de 300 ms).",
                               "Compare com a rede e o proxy da empresa se a lentidão persistir.")]
        except OSError as exc:
            error = exc
    return [dns, Check(key + "_tcp", "Conexão · " + component, "error",
                       f"Conexão TCP direta com {host} falhou: {error}.",
                       "Verifique conexão, firewall e proxy. O Teams pode usar uma rota diferente da sonda.")]


def tls_check(host: str) -> Check:
    try:
        with socket.create_connection((host, 443), timeout=2) as connection:
            with ssl.create_default_context().wrap_socket(connection, server_hostname=host) as secure:
                certificate = secure.getpeercert()
                issuer_parts = certificate.get("issuer", ())
                issuer = ", ".join(str(value) for group in issuer_parts for _key, value in group)
        return Check("tls_teams", "Certificado TLS do Teams", "ok",
                     f"Conexão criptografada validada com {host}. Emissor: {issuer or 'não informado'}.",
                     "O emissor identifica quem assinou o certificado; não prova que houve lentidão ou inspeção.")
    except (OSError, ssl.SSLError) as exc:
        return Check("tls_teams", "Certificado TLS do Teams", "error",
                     f"Falha ao validar a conexão criptografada: {exc}.",
                     "Confira data/hora do Windows, certificados, proxy e antivírus com a equipe de TI.")


def registry_value(hive, path: str, name: str):
    try:
        with winreg.OpenKey(hive, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def privacy_checks() -> list[Check]:
    checks = []
    root = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    policy_root = r"Software\Policies\Microsoft\Windows\AppPrivacy"
    for capability, label, policy in [
        ("microphone", "Microfone", "LetAppsAccessMicrophone"),
        ("webcam", "Câmera", "LetAppsAccessCamera"),
    ]:
        general = registry_value(winreg.HKEY_CURRENT_USER, root + "\\" + capability, "Value")
        teams = registry_value(winreg.HKEY_CURRENT_USER,
                               root + "\\" + capability + r"\MSTeams_8wekyb3d8bbwe", "Value")
        machine_policy = registry_value(winreg.HKEY_LOCAL_MACHINE, policy_root, policy)
        if machine_policy == 2 or general == "Deny" or teams == "Deny":
            state = "error"
            detail = (f"Acesso bloqueado no Windows (geral={general or 'não definido'}, "
                      f"Teams={teams or 'não definido'}, política={machine_policy}).")
            action = f"Abra Configurações do Windows → Privacidade e segurança → {label} e confira o acesso do Teams."
        elif general == "Allow" or teams == "Allow" or machine_policy == 1:
            state = "ok"
            detail = (f"Acesso permitido ou sob controle do usuário (geral={general or 'não definido'}, "
                      f"Teams={teams or 'não definido'}, política={machine_policy}).")
            action = "O Teams ainda pode ter um dispositivo diferente selecionado nas suas configurações."
        else:
            state = "info"
            detail = "Não foi possível confirmar a permissão efetiva pelas configurações registradas."
            action = f"Confira em Configurações do Windows → Privacidade e segurança → {label}."
        checks.append(Check("privacy_" + capability, "Privacidade · " + label, state, detail, action))
    return checks


def audio_checks() -> list[Check]:
    import comtypes
    from pycaw.pycaw import AudioUtilities, EDataFlow, ERole

    checks = []
    comtypes.CoInitialize()
    try:
        enumerator = AudioUtilities.GetDeviceEnumerator()
        for flow, key, label in [
            (EDataFlow.eCapture, "audio_microphone", "Microfone padrão de comunicação"),
            (EDataFlow.eRender, "audio_speaker", "Saída padrão de comunicação"),
        ]:
            try:
                endpoint = enumerator.GetDefaultAudioEndpoint(flow.value, ERole.eCommunications.value)
                device = AudioUtilities.CreateDevice(endpoint)
                name = str(device.FriendlyName or "Sem nome")
                volume = device.EndpointVolume
                muted = bool(volume.GetMute())
                level = round(volume.GetMasterVolumeLevelScalar() * 100)
                state = "warning" if muted or level < 10 else "ok"
                detail = f"{name}; {'mudo' if muted else 'ativo'}; volume {level}%."
                action = "Confira se o Teams escolheu este mesmo dispositivo em Configurações → Dispositivos."
                checks.append(Check(key, label, state, detail, action))
            except Exception as exc:
                checks.append(Check(key, label, "error", f"Nenhum dispositivo padrão disponível: {exc}.",
                                    "Confira o dispositivo no Windows e no Teams."))
    finally:
        comtypes.CoUninitialize()
    return checks


def teams_process_family() -> dict[int, psutil.Process]:
    processes = {}
    roots = set()
    for proc in psutil.process_iter(["name", "ppid"]):
        try:
            name = (proc.info["name"] or "").lower()
            processes[proc.pid] = proc
            if name in {"ms-teams.exe", "teams.exe"}:
                roots.add(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    family = set(roots)
    changed = True
    while changed:
        changed = False
        for pid, proc in processes.items():
            if pid not in family and proc.info.get("ppid") in family:
                family.add(pid)
                changed = True
    return {pid: processes[pid] for pid in family}


def teams_process_check(family: dict[int, psutil.Process] | None = None) -> Check:
    family = teams_process_family() if family is None else family
    if not family:
        return Check("teams_webview", "Teams e WebView2", "info",
                     "Aplicativo de desktop do Teams não detectado.")
    webviews = 0
    memory_mb = 0.0
    for proc in family.values():
        try:
            if proc.name().lower() == "msedgewebview2.exe":
                webviews += 1
            memory_mb += proc.memory_info().rss / 1024 ** 2
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return Check("teams_webview", "Teams e WebView2", "ok" if webviews else "warning",
                 f"Processos WebView2 ligados ao Teams: {webviews}; memória da família: {memory_mb:.0f} MB.",
                 "Se o Teams falhar ao abrir ou renderizar, confira WebView2 e bloqueios do antivírus.")


def teams_mixer_check(family: dict[int, psutil.Process] | None = None) -> Check:
    import comtypes
    from pycaw.pycaw import AudioUtilities

    family = teams_process_family() if family is None else family
    if not family:
        return Check("teams_mixer", "Volume do Teams no Windows", "info",
                     "Teams de desktop não detectado.")
    comtypes.CoInitialize()
    try:
        found = []
        for session in AudioUtilities.GetAllSessions():
            try:
                if session.ProcessId in family:
                    volume = session.SimpleAudioVolume
                    found.append((bool(volume.GetMute()), round(volume.GetMasterVolume() * 100)))
            except Exception:
                continue
    except Exception as exc:
        return Check("teams_mixer", "Volume do Teams no Windows", "info",
                     f"Misturador indisponível: {exc}.")
    finally:
        comtypes.CoUninitialize()
    if not found:
        return Check("teams_mixer", "Volume do Teams no Windows", "info",
                     "Nenhuma sessão do Teams no dispositivo de saída padrão neste momento.",
                     "O Teams pode estar ocioso ou usar outra saída de áudio.")
    muted = sum(is_muted or level < 10 for is_muted, level in found)
    levels = ", ".join(f"{'mudo' if is_muted else str(level) + '%'}" for is_muted, level in found)
    return Check("teams_mixer", "Volume do Teams no Windows", "warning" if muted else "ok",
                 f"{len(found)} sessão(ões) no misturador: {levels}.",
                 "Se estiver mudo ou muito baixo, confira o Misturador de volume do Windows.")


def fast_media_checks() -> list[Check]:
    checks = audio_checks()
    family = teams_process_family()
    checks.append(teams_process_check(family))
    checks.append(teams_mixer_check(family))
    return checks


def windows_snapshot() -> dict:
    if os.name != "nt":
        return {}
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$camera = @(Get-PnpDevice -Class Camera | Select-Object FriendlyName,Status)
$display = @(Get-PnpDevice -Class Display | Select-Object FriendlyName,Status)
$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | Select-Object InterfaceAlias,ServerAddresses)
$antivirus = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName)
$teams = Get-AppxPackage -Name MSTeams | Select-Object -First 1 Name,Version
[pscustomobject]@{ cameras=$camera; displays=$display; dns=$dns; antivirus=$antivirus; teams=$teams } | ConvertTo-Json -Depth 4 -Compress
"""
    result = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                            capture_output=True, text=True, timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Falha na consulta ao Windows")
    return json.loads(result.stdout)


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def device_checks(snapshot: dict) -> list[Check]:
    checks = []
    cameras = as_list(snapshot.get("cameras"))
    ready = [d.get("FriendlyName", "Câmera") for d in cameras if d.get("Status") == "OK"]
    if ready:
        checks.append(Check("camera_device", "Câmera no Windows", "ok",
                            "Disponível: " + ", ".join(ready) + "."))
    else:
        listed = ", ".join(f"{d.get('FriendlyName')} ({d.get('Status')})" for d in cameras)
        checks.append(Check("camera_device", "Câmera no Windows", "info",
                            "Nenhuma câmera pronta detectada." + (" Listadas: " + listed + "." if listed else ""),
                            "Se precisar de vídeo, confira a conexão da câmera e sua seleção no Teams."))
    displays = as_list(snapshot.get("displays"))
    working = [d.get("FriendlyName", "Placa de vídeo") for d in displays if d.get("Status") == "OK"]
    checks.append(Check("display_device", "Placa de vídeo", "ok" if working else "warning",
                        "Disponível: " + ", ".join(working) + "." if working else
                        "Nenhuma placa de vídeo pronta detectada pelo Windows.",
                        "Se a apresentação engasgar, confira o driver de vídeo e a carga do computador."))
    products = [d.get("displayName", "") for d in as_list(snapshot.get("antivirus"))]
    checks.append(Check("antivirus", "Antivírus registrado", "info",
                        ", ".join(products) if products else "Nenhum produto informado pelo Centro de Segurança.",
                        "A presença de antivírus não indica gargalo; compare picos de CPU com os horários dos engasgos."))
    package = snapshot.get("teams") or {}
    checks.append(Check("teams_version", "Aplicativo Teams", "ok" if package else "info",
                        f"Versão instalada: {package.get('Version')}" if package else
                        "Pacote do Teams não encontrado; pode estar usando o navegador ou outra edição."))
    return checks


def active_adapter() -> tuple[str | None, str]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("1.1.1.1", 53))
        local_ip = sock.getsockname()[0]
    names = [name for name, addrs in psutil.net_if_addrs().items()
             if any(addr.family == socket.AF_INET and addr.address == local_ip for addr in addrs)]
    return (names[0] if names else None), local_ip


def adapter_check() -> Check:
    try:
        name, local_ip = active_adapter()
        if not name:
            return Check("adapter", "Adaptador de rede", "info",
                         f"IP local {local_ip}; adaptador não identificado.")
        stats = psutil.net_if_stats().get(name)
        counters = psutil.net_io_counters(pernic=True).get(name)
        errors = sum((counters.errin, counters.errout, counters.dropin, counters.dropout)) if counters else 0
        previous = _last_adapter_errors.get(name, errors)
        delta = max(0, errors - previous)
        _last_adapter_errors[name] = errors
        detail = (f"{name}; IP {local_ip}; link {stats.speed if stats else '?'} Mb/s; "
                  f"novos erros/descartes desde a última verificação: {delta}.")
        state = "warning" if delta > 0 or not (stats and stats.isup) else "ok"
        return Check("adapter", "Adaptador de rede", state, detail,
                     "Se estiver usando Wi-Fi e houver perdas, teste uma conexão cabeada.")
    except OSError as exc:
        return Check("adapter", "Adaptador de rede", "warning", f"Rota de saída não detectada: {exc}.")


def direct_dns_query(server: str, name: str = "teams.cloud.microsoft", qtype: int = 1) -> float:
    identifier = random.randrange(65536)
    labels = b"".join(bytes((len(part),)) + part.encode("ascii") for part in name.split(".")) + b"\0"
    request = (struct.pack("!HHHHHH", identifier, 0x100, 1, 0, 0, 0)
               + labels + struct.pack("!HH", qtype, 1))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.8)
        start = time.monotonic()
        sock.sendto(request, (server, 53))
        while True:
            response, _address = sock.recvfrom(4096)
            if len(response) >= 12 and struct.unpack("!H", response[:2])[0] == identifier:
                if response[3] & 15:
                    raise OSError(f"Resposta DNS com código {response[3] & 15}")
                return (time.monotonic() - start) * 1000


def dns_server_checks(snapshot: dict) -> list[Check]:
    global _dns_round
    adapter, _local_ip = active_adapter()
    rows = [row for row in as_list(snapshot.get("dns")) if row.get("InterfaceAlias") == adapter]
    if not rows:
        return [Check("dns_server", "Servidor DNS do adaptador", "info",
                      "Endereços DNS não identificados para a rota ativa.")]
    servers = as_list(rows[0].get("ServerAddresses"))
    checks = []
    record_type, qtype = ("A", 1) if _dns_round % 2 == 0 else ("AAAA", 28)
    _dns_round += 1
    for index, server in enumerate(servers[:2]):
        history = _dns_history.setdefault(server, deque(maxlen=5))
        try:
            history.append((record_type, direct_dns_query(server, qtype=qtype)))
        except OSError:
            history.append((record_type, None))
        values = [value for _kind, value in history if value is not None]
        failures = sum(value is None for _kind, value in history)
        slow_count = sum(value > 100 for value in values)
        if failures >= 3:
            state = "error"
        elif failures >= 2 or slow_count >= 2:
            state = "warning"
        elif failures or slow_count:
            state = "info"
        else:
            state = "ok"
        median = f"mediana {sorted(values)[len(values) // 2]:.0f} ms; " if values else ""
        last = "sem resposta" if history[-1][1] is None else f"{history[-1][1]:.0f} ms"
        detail = (f"{server} no {adapter}: "
                  + f"última consulta {record_type} {last}; {median}"
                  + f"{failures}/{len(history)} falhas e {slow_count}/{len(history)} acima de 100 ms "
                  "nas últimas verificações UDP 53 (uma consulta por minuto).")
        checks.append(Check(f"dns_server_{index}",
                            "Servidor DNS " + ("principal" if index == 0 else "alternativo"),
                            state, detail,
                            "Se o alerta persistir, compare com os eventos 1014 do Windows e a rede no mesmo horário."))
    return checks


def proxy_check() -> Check:
    import urllib.request
    proxies = urllib.request.getproxies()
    found = bool(proxies)
    return Check("proxy", "Proxy do sistema", "info",
                 "Configurado para " + ", ".join(sorted(proxies)) + "." if found else "Não detectado.",
                 "Sondas TCP diretas podem divergir da rota usada pelo Teams quando há proxy.")


def audio_service_checks() -> list[Check]:
    checks = []
    for name, label in [("Audiosrv", "Áudio do Windows"),
                        ("AudioEndpointBuilder", "Gerenciador de dispositivos de áudio")]:
        try:
            status = psutil.win_service_get(name).status()
            checks.append(Check("service_" + name.lower(), label,
                                "ok" if status == "running" else "error",
                                f"Serviço {name}: {status}.",
                                "Se estiver parado, use o solucionador de problemas de áudio do Windows."))
        except Exception as exc:
            checks.append(Check("service_" + name.lower(), label, "info",
                                f"Estado não disponível: {exc}."))
    return checks


def disk_check() -> Check:
    drive = os.environ.get("SystemDrive", "C:") + "\\"
    usage = psutil.disk_usage(drive)
    free_gb = usage.free / 1024 ** 3
    free_pct = 100 - usage.percent
    state = "error" if free_pct < 5 else "warning" if free_pct < 10 else "ok"
    return Check("disk_space", "Espaço no disco do Windows", state,
                 f"Livre: {free_gb:.1f} GB ({free_pct:.0f}%).",
                 "Pouco espaço pode afetar cache, atualizações e logs do Teams.")


def hardware_event_check() -> Check:
    """Surface WHEA recurrence without treating corrected events as causal proof."""
    if os.name != "nt":
        return Check("whea_recent", "Alertas de hardware do Windows", "info",
                     "Verificação disponível somente no Windows.")
    script = r"""
$now = Get-Date
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; Id=17,18,19; StartTime=$now.AddDays(-30)} -ErrorAction SilentlyContinue)
$latest = $events | Select-Object -First 1
[pscustomobject]@{
    total=$events.Count
    desde_inicio=@($events | Where-Object { $_.TimeCreated -ge $boot }).Count
    recent=@($events | Where-Object { $_.TimeCreated -ge $now.AddMinutes(-15) }).Count
    critical=@($events | Where-Object { $_.Id -eq 18 -and $_.TimeCreated -ge $now.AddMinutes(-15) }).Count
    id=if ($latest) { $latest.Id } else { $null }
    horario=if ($latest) { $latest.TimeCreated.ToString('o') } else { $null }
} | ConvertTo-Json -Compress
"""
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                                capture_output=True, text=True, timeout=8,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "consulta falhou")
        summary = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired, RuntimeError) as exc:
        return Check("whea_recent", "Alertas de hardware do Windows", "info",
                     f"Consulta ao registro do Windows indisponível: {exc}.")
    total = summary["total"]
    recent = summary["recent"]
    if not total:
        return Check("whea_recent", "Alertas de hardware do Windows", "ok",
                     "Nenhum alerta WHEA nos últimos 30 dias.")
    state = "error" if summary["critical"] else "warning" if recent or total >= 10 else "info"
    return Check("whea_recent", "Alertas de hardware do Windows",
                 state,
                 f"{total} alerta(s) WHEA em 30 dias; {summary['desde_inicio']} desde a última inicialização; "
                 f"{recent} nos últimos 15 minutos; "
                 f"mais recente: evento {summary['id']} em {summary['horario']}. "
                 "Um erro corrigido não prova falha de áudio.",
                 "Se voltar a ocorrer, confira a estabilidade do computador e os drivers com o suporte técnico.")


def port_exhaustion_check() -> Check:
    """Expose TCP/UDP ephemeral-port allocation failures reported by Windows."""
    if os.name != "nt":
        return Check("port_exhaustion", "Portas de rede do Windows", "info",
                     "Verificação disponível somente no Windows.")
    script = r"""
$now = Get-Date
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Tcpip'; Id=4231,4266; StartTime=$now.AddDays(-7)} -ErrorAction SilentlyContinue)
$latest = $events | Select-Object -First 1
[pscustomobject]@{
    total=$events.Count
    desde_inicio=@($events | Where-Object { $_.TimeCreated -ge $boot }).Count
    udp=@($events | Where-Object { $_.Id -eq 4266 }).Count
    tcp=@($events | Where-Object { $_.Id -eq 4231 }).Count
    recent=@($events | Where-Object { $_.TimeCreated -ge $now.AddMinutes(-15) }).Count
    horario=if ($latest) { $latest.TimeCreated.ToString('o') } else { $null }
} | ConvertTo-Json -Compress
"""
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                                capture_output=True, text=True, timeout=8,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "consulta falhou")
        summary = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired, RuntimeError) as exc:
        return Check("port_exhaustion", "Portas de rede do Windows", "info",
                     f"Consulta ao registro do Windows indisponível: {exc}.")
    if not summary["total"]:
        return Check("port_exhaustion", "Portas de rede do Windows", "ok",
                     "Nenhuma falha de alocação de portas TCP/UDP nos últimos 7 dias.")
    state = "warning" if summary["recent"] or summary["total"] >= 2 else "info"
    return Check("port_exhaustion", "Portas de rede do Windows", state,
                 f"Falhas de alocação em 7 dias: {summary['udp']} UDP, {summary['tcp']} TCP; "
                 f"{summary['desde_inicio']} desde a última inicialização; "
                 f"{summary['recent']} nos últimos 15 minutos; última em {summary['horario']}. "
                 "O histórico não significa que as portas estão esgotadas agora.",
                 "Se ocorrer durante uma chamada, identifique o processo que abre muitas conexões.")


def dns_timeout_event_check() -> Check:
    """Report Windows DNS timeouts, independently of the monitor's own probes."""
    if os.name != "nt":
        return Check("dns_timeout_event", "Falhas de DNS do Windows", "info",
                     "Verificação disponível somente no Windows.")
    script = r"""
$now = Get-Date
$events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-DNS-Client'; Id=1014; StartTime=$now.AddDays(-1)} -ErrorAction SilentlyContinue)
$latest = $events | Select-Object -First 1
$server = $null
if ($latest -and $latest.Properties.Count -gt 2) {
    $bytes = $latest.Properties[2].Value
    if ($bytes -and $bytes.Length -ge 8 -and $bytes[0] -eq 2) {
        $server = @($bytes[4..7]) -join '.'
    }
}
[pscustomobject]@{
    total=$events.Count
    recent=@($events | Where-Object { $_.TimeCreated -ge $now.AddMinutes(-15) }).Count
    horario=if ($latest) { $latest.TimeCreated.ToString('o') } else { $null }
    servidor=$server
} | ConvertTo-Json -Compress
"""
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                                capture_output=True, text=True, timeout=8,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "consulta falhou")
        summary = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired, RuntimeError) as exc:
        return Check("dns_timeout_event", "Falhas de DNS do Windows", "info",
                     f"Consulta ao registro do Windows indisponível: {exc}.")
    if not summary["total"]:
        return Check("dns_timeout_event", "Falhas de DNS do Windows", "ok",
                     "Nenhuma consulta DNS sem resposta registrada pelo Windows nas últimas 24 horas.")
    state = "error" if summary["recent"] >= 3 else "warning"
    return Check("dns_timeout_event", "Falhas de DNS do Windows", state,
                 f"{summary['total']} consulta(s) DNS sem resposta em 24 horas; "
                 f"{summary['recent']} nos últimos 15 minutos; última em {summary['horario']}; "
                 f"servidor {summary['servidor'] or 'não identificado'}. "
                 "O evento não demonstra que o áudio do Teams foi afetado.",
                 "Se repetir durante uma chamada, compare os servidores DNS e a qualidade da rede no mesmo horário.")


def run_diagnostics() -> list[Check]:
    checks = []
    for function in (privacy_checks, audio_checks, audio_service_checks):
        try:
            checks.extend(function())
        except Exception as exc:
            checks.append(Check(function.__name__, function.__name__, "info",
                                f"Verificação indisponível: {exc}."))
    for function in (adapter_check, proxy_check, disk_check,
                     hardware_event_check, port_exhaustion_check, dns_timeout_event_check):
        try:
            checks.append(function())
        except Exception as exc:
            checks.append(Check(function.__name__, function.__name__, "info",
                                f"Verificação indisponível: {exc}."))
    dns_checks = []
    try:
        snapshot = windows_snapshot()
        checks.extend(device_checks(snapshot))
        dns_checks = dns_server_checks(snapshot)
        checks.extend(dns_checks)
    except Exception as exc:
        checks.append(Check("windows_devices", "Dispositivos no Windows", "info",
                            f"Verificação indisponível: {exc}."))
    teams_checks = endpoint_checks("service_teams", "Serviço do Teams", "teams.cloud.microsoft")
    if (teams_checks[0].state == "warning" and dns_checks
            and all(check.state == "ok" for check in dns_checks)):
        teams_checks[0].action = ("Os servidores DNS responderam bem no teste direto; "
                                  "o atraso pode estar na resolução local do Windows, cache ou carga do PC.")
    checks.extend(teams_checks)
    checks.extend(endpoint_checks("service_identity", "Autenticação Microsoft", "login.microsoftonline.com"))
    checks.extend(endpoint_checks("service_graph", "Microsoft Graph", "graph.microsoft.com"))
    checks.append(tls_check("teams.cloud.microsoft"))
    family = teams_process_family()
    checks.append(teams_process_check(family))
    checks.append(teams_mixer_check(family))
    return checks
