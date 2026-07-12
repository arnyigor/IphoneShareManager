#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iPhone SMB Share Manager for Windows

Что делает программа:
- выбирает папку Windows и публикует её как SMB-ресурс;
- создаёт/обновляет отдельного локального пользователя;
- назначает NTFS-права и права SMB;
- выводит адреса для подключения из приложения «Файлы» на iPhone;
- проверяет службу SMB, порт 445, сетевой профиль, ресурс и права;
- показывает активные SMB-сессии и открытые по сети файлы;
- приблизительно отслеживает передачу: активный файл, изменение размера
  и общую сетевую скорость адаптера.

Программа использует только стандартную библиотеку Python и штатные
команды Windows/PowerShell.
"""

from __future__ import annotations

import base64
import ctypes
import json
import ntpath
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    X,
    BooleanVar,
    StringVar,
    Tk,
    Toplevel,
    filedialog,
    messagebox,
)
from tkinter import ttk
from typing import Any


APP_NAME = "iPhone SMB Share Manager"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "IPhoneSmbShareManager"
CONFIG_PATH = APP_DIR / "config.json"
LOG_PATH = APP_DIR / "app.log"

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def ensure_app_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def append_file_log(message: str) -> None:
    ensure_app_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(f"[{timestamp}] {message}\n")
    except OSError:
        pass


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Перезапускает текущий Python-скрипт с UAC."""
    if not is_windows():
        return False

    executable = sys.executable
    script_path = str(Path(__file__).resolve())
    params = subprocess.list2cmdline([script_path, *sys.argv[1:]])

    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            params,
            str(Path(script_path).parent),
            1,
        )
        return result > 32
    except Exception:
        return False


def run_process(
    args: list[str],
    *,
    input_text: str | None = None,
    env_extra: dict[str, str] | None = None,
    timeout: int = 60,
) -> CommandResult:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    try:
        completed = subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return CommandResult(
            completed.returncode,
            completed.stdout.strip(),
            completed.stderr.strip(),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            124,
            (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            f"Команда не завершилась за {timeout} секунд.",
        )
    except FileNotFoundError as exc:
        return CommandResult(127, "", str(exc))
    except Exception as exc:
        return CommandResult(1, "", f"{type(exc).__name__}: {exc}")


def run_powershell(
    script: str,
    *,
    env_extra: dict[str, str] | None = None,
    timeout: int = 60,
) -> CommandResult:
    # -EncodedCommand принимает UTF-16LE и корректно работает с русскими путями
    # независимо от текущей кодовой страницы Windows.
    prelude = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
"""
    full_script = prelude + "\n" + script
    encoded = base64.b64encode(full_script.encode("utf-16le")).decode("ascii")
    return run_process(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        env_extra=env_extra,
        timeout=timeout,
    )


def parse_json_output(text: str) -> Any:
    if not text.strip():
        return None

    # PowerShell иногда добавляет предупреждение перед JSON. Ищем первый JSON-токен.
    candidates = []
    for token in ("[", "{", "null", '"'):
        pos = text.find(token)
        if pos >= 0:
            candidates.append(pos)
    start = min(candidates) if candidates else 0

    payload = text[start:].strip()
    return json.loads(payload)


def sanitize_share_name(value: str) -> str:
    value = value.strip()
    value = re.sub(r'[\\/:*?"<>|,\[\];=+]', "_", value)
    value = re.sub(r"\s+", "_", value)
    value = value.strip("._ ")
    return value[:80] or "iPhoneShare"


def derive_share_name(folder: str) -> str:
    # ntpath корректно разбирает Windows-пути даже при статической проверке
    # программы на другой ОС.
    name = ntpath.basename(folder.rstrip("\\/"))
    return sanitize_share_name(name or "iPhoneShare")


def format_bytes(value: float) -> str:
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    size = float(value)
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            if unit == "Б":
                return f"{size:.0f} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} ТБ"


def load_config() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(data: dict[str, Any]) -> None:
    ensure_app_dir()
    CONFIG_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def get_computer_name() -> str:
    return os.environ.get("COMPUTERNAME") or socket.gethostname()


class ShareManager:
    def create_or_update_user(self, username: str, password: str) -> CommandResult:
        script = r"""
$userName = $env:SMB_USER
$passwordPlain = $env:SMB_PASSWORD

if ([string]::IsNullOrWhiteSpace($userName)) {
    throw "Не указано имя пользователя."
}
if ([string]::IsNullOrEmpty($passwordPlain)) {
    throw "Пароль не может быть пустым."
}

$securePassword = ConvertTo-SecureString $passwordPlain -AsPlainText -Force
Remove-Item Env:SMB_PASSWORD -ErrorAction SilentlyContinue

$user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
if ($null -eq $user) {
    New-LocalUser `
        -Name $userName `
        -Password $securePassword `
        -AccountNeverExpires `
        -PasswordNeverExpires `
        -Description "Доступ к SMB-папке для iPhone" | Out-Null
    $action = "created"
} else {
    Set-LocalUser -Name $userName -Password $securePassword
    Enable-LocalUser -Name $userName
    $action = "updated"
}

[pscustomobject]@{
    Action = $action
    User = $userName
    Enabled = (Get-LocalUser -Name $userName).Enabled
} | ConvertTo-Json -Compress
"""
        return run_powershell(
            script,
            env_extra={"SMB_USER": username, "SMB_PASSWORD": password},
        )

    def grant_ntfs_access(self, folder: str, username: str) -> CommandResult:
        script = r"""
$path = $env:SMB_PATH
$userName = $env:SMB_USER
$identity = "$env:COMPUTERNAME\$userName"

if (-not (Test-Path -LiteralPath $path -PathType Container)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

$acl = Get-Acl -LiteralPath $path
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $identity,
    "Modify",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl -LiteralPath $path -AclObject $acl

# Для уже существующих подпапок/файлов явно проталкиваем наследуемое право.
# Это исправляет ситуацию, когда iPhone видит ресурс, но не видит вложенные папки
# из-за старых ACL или отключенного наследования на части элементов.
$grant = ('{0}:(OI)(CI)M' -f $identity)
$icaclsOutput = & icacls $path /grant $grant /T /C 2>&1
$icaclsExitCode = $LASTEXITCODE
if ($icaclsExitCode -gt 1) {
    throw "icacls завершился с кодом $icaclsExitCode`: $($icaclsOutput -join '; ')"
}

[pscustomobject]@{
    Path = $path
    Identity = $identity
    Rights = "Modify"
    RecursiveAclExitCode = $icaclsExitCode
} | ConvertTo-Json -Compress
"""
        return run_powershell(
            script,
            env_extra={"SMB_PATH": folder, "SMB_USER": username},
        )

    def create_or_update_share(
        self,
        folder: str,
        share_name: str,
        username: str,
    ) -> CommandResult:
        script = r"""
$path = $env:SMB_PATH
$shareName = $env:SMB_SHARE
$userName = $env:SMB_USER
$identity = "$env:COMPUTERNAME\$userName"

$existing = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
$action = "created"

if ($null -ne $existing) {
    if ($existing.Path -ne $path) {
        Remove-SmbShare -Name $shareName -Force
        $existing = $null
        $action = "recreated"
    } else {
        $action = "updated"
    }
}

if ($null -eq $existing) {
    New-SmbShare `
        -Name $shareName `
        -Path $path `
        -FullAccess $identity `
        -Description "Обмен файлами Windows-iPhone" `
        -CachingMode None | Out-Null
} else {
    Grant-SmbShareAccess `
        -Name $shareName `
        -AccountName $identity `
        -AccessRight Full `
        -Force | Out-Null
}

# Убираем слишком широкие права, если они были добавлены ранее.
foreach ($account in @("Everyone", "Все")) {
    try {
        Revoke-SmbShareAccess -Name $shareName -AccountName $account -Force -ErrorAction Stop
    } catch {
        # Игнорируем: локализованное имя группы может отсутствовать.
    }
}

$share = Get-SmbShare -Name $shareName
$access = Get-SmbShareAccess -Name $shareName |
    Select-Object AccountName, AccessControlType, AccessRight

[pscustomobject]@{
    Action = $action
    Name = $share.Name
    Path = $share.Path
    Access = @($access)
} | ConvertTo-Json -Depth 5 -Compress
"""
        return run_powershell(
            script,
            env_extra={
                "SMB_PATH": folder,
                "SMB_SHARE": share_name,
                "SMB_USER": username,
            },
        )

    def enable_smb_firewall_rules(self) -> CommandResult:
        script = r"""
$rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like "FPS-SMB-In-TCP*" -or
        $_.Name -like "FPS-NB*" -or
        $_.DisplayGroup -match "File and Printer Sharing|Общий доступ к файлам и принтерам"
    }

if ($rules) {
    $rules | Enable-NetFirewallRule
}

[pscustomobject]@{
    EnabledRules = @($rules).Count
} | ConvertTo-Json -Compress
"""
        return run_powershell(script)

    def set_active_profiles_private(self) -> CommandResult:
        script = r"""
$profiles = Get-NetConnectionProfile |
    Where-Object { $_.IPv4Connectivity -ne "Disconnected" }

foreach ($profile in $profiles) {
    if ($profile.NetworkCategory -ne "DomainAuthenticated") {
        Set-NetConnectionProfile `
            -InterfaceIndex $profile.InterfaceIndex `
            -NetworkCategory Private
    }
}

Get-NetConnectionProfile |
    Where-Object { $_.IPv4Connectivity -ne "Disconnected" } |
    Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity |
    ConvertTo-Json -Depth 4 -Compress
"""
        return run_powershell(script)

    def remove_share(self, share_name: str) -> CommandResult:
        script = r"""
$shareName = $env:SMB_SHARE
$share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
if ($null -eq $share) {
    [pscustomobject]@{ Removed = $false; Reason = "not_found" } |
        ConvertTo-Json -Compress
    exit 0
}
Remove-SmbShare -Name $shareName -Force
[pscustomobject]@{ Removed = $true; Name = $shareName } |
    ConvertTo-Json -Compress
"""
        return run_powershell(script, env_extra={"SMB_SHARE": share_name})

    def inspect_status(
        self,
        folder: str,
        share_name: str,
        username: str,
    ) -> CommandResult:
        script = r"""
$path = $env:SMB_PATH
$shareName = $env:SMB_SHARE
$userName = $env:SMB_USER
$identity = "$env:COMPUTERNAME\$userName"

$service = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
$share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
$shareAccess = @()
if ($share) {
    $shareAccess = @(
        Get-SmbShareAccess -Name $shareName -ErrorAction SilentlyContinue |
        Select-Object AccountName, AccessControlType, AccessRight
    )
}

$shareCandidatesByPath = @(
    Get-SmbShare -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Special -eq $false -and
        ($_.Path.TrimEnd('\\') -ieq $path.TrimEnd('\\'))
    } |
    Select-Object Name, Path, Description
)

$user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue

$profiles = @(
    Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Where-Object { $_.IPv4Connectivity -ne "Disconnected" } |
    Select-Object Name, InterfaceAlias, InterfaceIndex,
                  NetworkCategory, IPv4Connectivity
)

$ipItems = @(
    Get-NetIPConfiguration -ErrorAction SilentlyContinue |
    Where-Object {
        $_.NetAdapter.Status -eq "Up" -and
        $null -ne $_.IPv4Address -and
        $null -ne $_.IPv4DefaultGateway
    } |
    ForEach-Object {
        foreach ($ip in $_.IPv4Address) {
            if ($ip.IPAddress -notmatch "^127\." -and
                $ip.IPAddress -notmatch "^169\.254\.") {
                [pscustomobject]@{
                    IPAddress = $ip.IPAddress
                    InterfaceAlias = $_.InterfaceAlias
                    PrefixLength = $ip.PrefixLength
                }
            }
        }
    }
)

$port445 = @(
    Get-NetTCPConnection -State Listen -LocalPort 445 -ErrorAction SilentlyContinue
).Count -gt 0

$diagnostics = New-Object System.Collections.Generic.List[string]

$aclEntry = $null
if (Test-Path -LiteralPath $path) {
    try {
        $aclEntry = Get-Acl -LiteralPath $path -ErrorAction Stop |
            Select-Object -ExpandProperty Access |
            Where-Object {
                $_.IdentityReference.Value -ieq $identity -or
                $_.IdentityReference.Value -ieq $userName
            } |
            Select-Object -First 1 IdentityReference, FileSystemRights,
                                   AccessControlType, IsInherited
    } catch {
        $diagnostics.Add("ACL: $($_.Exception.Message)")
    }
}

$folderItems = @()
if (Test-Path -LiteralPath $path) {
    try {
        $folderItems = @(
            Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop |
            Select-Object -First 80 `
                Name,
                @{Name="Type"; Expression={ if ($_.PSIsContainer) { "Folder" } else { "File" } }},
                Length,
                LastWriteTime
        )
    } catch {
        $diagnostics.Add("FolderList: $($_.Exception.Message)")
    }
}

$sessions = @()
try {
    $sessions = @(
        Get-SmbSession -ErrorAction Stop |
        Select-Object `
            @{Name="Source"; Expression={ "SMB" }},
            ClientComputerName, ClientUserName, NumOpens,
            SecondsExists, Dialect, Encrypted, Signed
    )
} catch {
    $diagnostics.Add("Get-SmbSession: $($_.Exception.Message)")
}

$tcpConnections = @()
try {
    $tcpConnections = @(
        Get-NetTCPConnection -ErrorAction Stop |
        Where-Object { $_.State -eq "Established" -and $_.LocalPort -eq 445 } |
        Select-Object RemoteAddress, RemotePort, State, OwningProcess
    )
} catch {
    $diagnostics.Add("Get-NetTCPConnection: $($_.Exception.Message)")
}

if (@($tcpConnections).Count -eq 0) {
    try {
        $tcpConnections = @(
            & netstat.exe -ano -p tcp |
            Select-String -Pattern "ESTABLISHED" |
            ForEach-Object {
                $parts = ($_.Line.Trim() -split "\s+")
                if ($parts.Count -ge 5 -and $parts[1] -match ":445$") {
                    $remote = $parts[2]
                    $remoteAddress = $remote -replace ":\d+$", ""
                    [pscustomobject]@{
                        RemoteAddress = $remoteAddress
                        RemotePort = $null
                        State = "Established"
                        OwningProcess = $parts[4]
                    }
                }
            }
        )
    } catch {
        $diagnostics.Add("netstat: $($_.Exception.Message)")
    }
}

# Fallback: если Get-SmbSession недоступен без администратора, показываем хотя бы
# реальные TCP-подключения к SMB-порту 445, чтобы активный клиент не пропадал из UI.
if (@($sessions).Count -eq 0 -and @($tcpConnections).Count -gt 0) {
    $sessions = @(
        $tcpConnections | ForEach-Object {
            [pscustomobject]@{
                Source = "TCP445"
                ClientComputerName = $_.RemoteAddress
                ClientUserName = "неизвестно"
                NumOpens = $null
                SecondsExists = $null
                Dialect = "нужны права администратора для Get-SmbSession"
                Encrypted = $null
                Signed = $null
            }
        }
    )
}

$openFiles = @()
try {
    $openFiles = @(
        Get-SmbOpenFile -ErrorAction Stop |
        Select-Object ClientComputerName, ClientUserName, Path,
                      Permissions, SessionId, FileId
    )
} catch {
    $diagnostics.Add("Get-SmbOpenFile: $($_.Exception.Message)")
}

[pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    ServerService = if ($service) { $service.Status.ToString() } else { "NotFound" }
    Port445Listening = $port445
    FolderExists = Test-Path -LiteralPath $path -PathType Container
    UserExists = $null -ne $user
    UserEnabled = if ($user) { $user.Enabled } else { $false }
    ShareExists = $null -ne $share
    SharePath = if ($share) { $share.Path } else { $null }
    ShareAccess = $shareAccess
    ShareCandidatesByPath = $shareCandidatesByPath
    AclEntry = $aclEntry
    Profiles = $profiles
    IPAddresses = $ipItems
    Sessions = $sessions
    OpenFiles = $openFiles
    FolderItems = $folderItems
    Diagnostics = @($diagnostics)
} | ConvertTo-Json -Depth 8 -Compress
"""
        return run_powershell(
            script,
            env_extra={
                "SMB_PATH": folder,
                "SMB_SHARE": share_name,
                "SMB_USER": username,
            },
        )

    def get_adapter_stats(self) -> CommandResult:
        script = r"""
$items = @(
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq "Up" } |
    ForEach-Object {
        $s = Get-NetAdapterStatistics -Name $_.Name
        [pscustomobject]@{
            Name = $_.Name
            InterfaceDescription = $_.InterfaceDescription
            ReceivedBytes = [int64]$s.ReceivedBytes
            SentBytes = [int64]$s.SentBytes
        }
    }
)
$items | ConvertTo-Json -Depth 4 -Compress
"""
        return run_powershell(script)

    def unc_read_write_test(self, share_name: str) -> tuple[str, str]:
        unc_dir = Path(rf"\\localhost\{share_name}")
        test_name = f".iphone_smb_test_{os.getpid()}_{int(time.time())}.tmp"
        unc_file = unc_dir / test_name
        payload = os.urandom(64 * 1024)

        try:
            if not unc_dir.exists():
                return "warning", f"UNC-путь недоступен для текущего пользователя Windows: {unc_dir}"
            unc_file.write_bytes(payload)
            read_back = unc_file.read_bytes()
            if read_back != payload:
                return "error", "Контрольная запись выполнена, но данные при чтении отличаются."
            unc_file.unlink(missing_ok=True)
            return "ok", "Контрольная запись и чтение через \\\\localhost прошли успешно."
        except PermissionError as exc:
            return (
                "warning",
                "Проверка записи через \\\\localhost не выполнена: текущий пользователь "
                "Windows не имеет доступа к ресурсу. Это нормально, если iPhone "
                f"подключается под отдельным SMB-пользователем. ({exc})",
            )
        except Exception as exc:
            try:
                unc_file.unlink(missing_ok=True)
            except Exception:
                pass
            return "error", f"Тест UNC завершился ошибкой: {type(exc).__name__}: {exc}"


class App:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1050x760")
        self.root.minsize(900, 650)

        self.manager = ShareManager()
        self.ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.stop_monitor = threading.Event()
        self.monitor_thread: threading.Thread | None = None
        self.last_adapter_sample: dict[str, tuple[int, int, float]] = {}
        self.file_size_history: dict[str, tuple[int, float]] = {}
        self.monitor_settings_lock = threading.Lock()

        config = load_config()

        self.folder_var = StringVar(value=config.get("folder", r"I:\Files"))
        self.share_var = StringVar(value=config.get("share_name", "Files"))
        self.user_var = StringVar(value=config.get("username", "transfer"))
        self.password_var = StringVar()
        self.show_password_var = BooleanVar(value=False)
        self.make_private_var = BooleanVar(value=False)

        self.monitor_settings = {
            "folder": self.folder_var.get(),
            "share_name": self.share_var.get(),
            "username": self.user_var.get(),
        }
        self.folder_var.trace_add("write", self._sync_monitor_settings)
        self.share_var.trace_add("write", self._sync_monitor_settings)
        self.user_var.trace_add("write", self._sync_monitor_settings)

        self.status_share_var = StringVar(value="Общий ресурс: не проверен")
        self.status_connection_var = StringVar(value="iPhone: не подключён")
        self.status_transfer_var = StringVar(value="Передача: нет данных")
        self.status_network_var = StringVar(value="Сеть: не проверена")

        self._build_ui()
        self.root.after(150, self._process_ui_queue)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.log("Программа запущена.")
        if not is_admin():
            self.log("ПРЕДУПРЕЖДЕНИЕ: программа запущена без прав администратора.")

        self.start_monitor()

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=BOTH, expand=True)

        setup = ttk.LabelFrame(main, text="Настройка общего доступа", padding=10)
        setup.pack(fill=X)

        ttk.Label(setup, text="Папка Windows:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(setup, textvariable=self.folder_var).grid(
            row=0, column=1, sticky="ew", padx=8, pady=4
        )
        ttk.Button(setup, text="Выбрать…", command=self.choose_folder).grid(
            row=0, column=2, pady=4
        )

        ttk.Label(setup, text="Имя SMB-ресурса:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(setup, textvariable=self.share_var, width=30).grid(
            row=1, column=1, sticky="w", padx=8, pady=4
        )

        ttk.Label(setup, text="Локальный пользователь:").grid(
            row=2, column=0, sticky="w", pady=4
        )
        ttk.Entry(setup, textvariable=self.user_var, width=30).grid(
            row=2, column=1, sticky="w", padx=8, pady=4
        )

        ttk.Label(setup, text="Пароль пользователя:").grid(
            row=3, column=0, sticky="w", pady=4
        )
        password_frame = ttk.Frame(setup)
        password_frame.grid(row=3, column=1, sticky="ew", padx=8, pady=4)
        self.password_entry = ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            show="•",
        )
        self.password_entry.pack(side=LEFT, fill=X, expand=True)
        ttk.Checkbutton(
            password_frame,
            text="Показать",
            variable=self.show_password_var,
            command=self.toggle_password,
        ).pack(side=RIGHT, padx=(8, 0))

        ttk.Checkbutton(
            setup,
            text="Автоматически перевести активную сеть Windows в профиль «Частная»",
            variable=self.make_private_var,
        ).grid(row=4, column=1, sticky="w", padx=8, pady=4)

        setup.columnconfigure(1, weight=1)

        actions = ttk.Frame(main)
        actions.pack(fill=X, pady=(10, 6))

        ttk.Button(
            actions,
            text="Создать / обновить доступ",
            command=self.setup_share,
        ).pack(side=LEFT, padx=(0, 6))

        ttk.Button(
            actions,
            text="Починить ресурс без пароля",
            command=self.repair_share_without_password,
        ).pack(side=LEFT, padx=6)

        ttk.Button(
            actions,
            text="Проверить всё",
            command=self.run_full_check,
        ).pack(side=LEFT, padx=6)

        ttk.Button(
            actions,
            text="Открыть папку",
            command=self.open_folder,
        ).pack(side=LEFT, padx=6)

        ttk.Button(
            actions,
            text="Скопировать данные для iPhone",
            command=self.copy_connection_info,
        ).pack(side=LEFT, padx=6)

        ttk.Button(
            actions,
            text="Удалить общий ресурс",
            command=self.remove_share,
        ).pack(side=RIGHT, padx=(6, 0))

        status = ttk.LabelFrame(main, text="Текущее состояние", padding=10)
        status.pack(fill=X, pady=(0, 8))

        ttk.Label(status, textvariable=self.status_share_var).pack(anchor="w")
        ttk.Label(status, textvariable=self.status_connection_var).pack(anchor="w")
        ttk.Label(status, textvariable=self.status_transfer_var).pack(anchor="w")
        ttk.Label(status, textvariable=self.status_network_var).pack(anchor="w")

        notebook = ttk.Notebook(main)
        notebook.pack(fill=BOTH, expand=True)

        log_tab = ttk.Frame(notebook)
        sessions_tab = ttk.Frame(notebook)
        help_tab = ttk.Frame(notebook)

        notebook.add(log_tab, text="Журнал и данные подключения")
        notebook.add(sessions_tab, text="Активные подключения")
        notebook.add(help_tab, text="Инструкция")

        log_toolbar = ttk.Frame(log_tab)
        log_toolbar.pack(fill=X, padx=4, pady=(4, 0))
        ttk.Button(
            log_toolbar,
            text="Скопировать журнал",
            command=self.copy_log_to_clipboard,
        ).pack(side=LEFT, padx=(0, 6))
        ttk.Button(
            log_toolbar,
            text="Открыть файл журнала",
            command=self.open_log_file,
        ).pack(side=LEFT, padx=6)
        ttk.Button(
            log_toolbar,
            text="Сохранить журнал как…",
            command=self.save_log_as,
        ).pack(side=LEFT, padx=6)

        sessions_toolbar = ttk.Frame(sessions_tab)
        sessions_toolbar.pack(fill=X, padx=4, pady=(4, 0))
        ttk.Button(
            sessions_toolbar,
            text="Скопировать подключения",
            command=self.copy_sessions_to_clipboard,
        ).pack(side=LEFT, padx=(0, 6))
        ttk.Button(
            sessions_toolbar,
            text="Обновить",
            command=self.run_full_check,
        ).pack(side=LEFT, padx=6)

        self.log_text = self._make_text_widget(log_tab)
        self.sessions_text = self._make_text_widget(sessions_tab)
        help_text = self._make_text_widget(help_tab)

        help_text.insert(
            END,
            """КАК ИСПОЛЬЗОВАТЬ

1. Выберите папку Windows.
2. Укажите короткое имя SMB-ресурса, например Files.
3. Укажите локального пользователя Windows, например transfer.
4. Введите пароль. Он используется для создания/обновления пользователя и
   не сохраняется в конфигурационный файл.
5. Нажмите «Создать / обновить доступ».
6. На iPhone откройте:
   Файлы → Обзор → ⋯ → Подключиться к серверу.
7. Введите адрес вида:
   smb://192.168.1.50/Files
8. Выберите «Зарегистрированный пользователь» и введите:
   ИМЯ-КОМПЬЮТЕРА\\transfer
   и заданный пароль.

ВАЖНО О ПРОГРЕССЕ ПЕРЕДАЧИ

iOS и Windows SMB не предоставляют внешней программе достоверный процент
передачи файла, которую начал iPhone. Программа показывает максимально
доступные признаки:

- активную SMB-сессию;
- открытые по сети файлы;
- текущий размер растущего файла на диске;
- скорость изменения этого размера;
- суммарную входящую/исходящую скорость физических сетевых адаптеров.

Для загрузки с Windows на iPhone точный процент обычно виден только в самом
приложении «Файлы». На Windows можно увидеть факт открытия файла и общую
сетевую активность, но не подтверждённое число переданных байт для конкретного
файла.

БЕЗОПАСНОСТЬ

Используйте общий доступ только в доверенной домашней сети. Не переводите
сеть гостиницы, кафе или аэропорта в профиль «Частная». Не публикуйте корни
дисков C:\\, D:\\ и административные ресурсы C$, ADMIN$ для iPhone.
""",
        )
        help_text.configure(state="disabled")

    def _make_text_widget(self, parent: ttk.Frame):
        frame = ttk.Frame(parent)
        frame.pack(fill=BOTH, expand=True)
        text = __import__("tkinter").Text(
            frame,
            wrap="word",
            font=("Consolas", 10),
            padx=8,
            pady=8,
        )
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill="y")
        return text

    def log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        self.log_text.insert(END, line + "\n")
        self.log_text.see(END)
        append_file_log(message)

    def queue_log(self, message: str) -> None:
        self.ui_queue.put(("log", message))

    def _copy_text_to_clipboard(self, text: str, success_message: str) -> None:
        if not text.strip():
            messagebox.showinfo(APP_NAME, "Нечего копировать.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log(success_message)

    def copy_log_to_clipboard(self) -> None:
        self._copy_text_to_clipboard(
            self.log_text.get("1.0", END),
            "Журнал скопирован в буфер обмена.",
        )

    def copy_sessions_to_clipboard(self) -> None:
        self._copy_text_to_clipboard(
            self.sessions_text.get("1.0", END),
            "Список подключений скопирован в буфер обмена.",
        )

    def open_log_file(self) -> None:
        try:
            ensure_app_dir()
            LOG_PATH.touch(exist_ok=True)
            os.startfile(str(LOG_PATH))  # type: ignore[attr-defined]
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def save_log_as(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Сохранить журнал",
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
            initialfile="iphone_smb_share_manager_log.txt",
        )
        if not path:
            return
        try:
            Path(path).write_text(self.log_text.get("1.0", END), encoding="utf-8")
            self.log(f"Журнал сохранён: {path}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def toggle_password(self) -> None:
        self.password_entry.configure(show="" if self.show_password_var.get() else "•")

    def _sync_monitor_settings(self, *_args: Any) -> None:
        # Вызывается главным потоком Tk.
        with self.monitor_settings_lock:
            self.monitor_settings = {
                "folder": self.folder_var.get().strip().strip('"'),
                "share_name": sanitize_share_name(self.share_var.get()),
                "username": self.user_var.get().strip(),
            }

    def choose_folder(self) -> None:
        initial = self.folder_var.get().strip()
        if not Path(initial).exists():
            initial = str(Path.home())
        folder = filedialog.askdirectory(initialdir=initial)
        if folder:
            self.folder_var.set(folder)
            self.share_var.set(derive_share_name(folder))

    def validate_inputs(self, require_password: bool = True) -> tuple[str, str, str, str]:
        folder = self.folder_var.get().strip().strip('"')
        share_name = sanitize_share_name(self.share_var.get())
        username = self.user_var.get().strip()
        password = self.password_var.get()

        if not folder:
            raise ValueError("Не выбрана папка.")
        if not Path(folder).is_absolute():
            raise ValueError("Путь к папке должен быть абсолютным.")
        if not share_name:
            raise ValueError("Не указано имя SMB-ресурса.")
        if not username or any(ch in username for ch in r'\/[]:;|=,+*?<>@"'):
            raise ValueError("Укажите корректное имя локального пользователя Windows.")
        if require_password and not password:
            raise ValueError("Введите пароль пользователя.")
        if require_password and len(password) < 6:
            raise ValueError("Используйте пароль длиной не менее 6 символов.")

        self.share_var.set(share_name)
        return folder, share_name, username, password

    def save_current_config(self) -> None:
        save_config(
            {
                "folder": self.folder_var.get().strip(),
                "share_name": self.share_var.get().strip(),
                "username": self.user_var.get().strip(),
            }
        )

    def run_background(self, func, *, success_message: str | None = None) -> None:
        def worker() -> None:
            try:
                func()
                if success_message:
                    self.queue_log(success_message)
            except Exception as exc:
                self.ui_queue.put(
                    (
                        "error",
                        f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}",
                    )
                )

        threading.Thread(target=worker, daemon=True).start()

    def setup_share(self) -> None:
        if not is_windows():
            messagebox.showerror(APP_NAME, "Эта программа предназначена только для Windows.")
            return
        if not is_admin():
            if messagebox.askyesno(
                APP_NAME,
                "Для настройки SMB нужны права администратора.\n\n"
                "Перезапустить программу с запросом UAC?",
            ):
                if relaunch_as_admin():
                    self.root.destroy()
                else:
                    messagebox.showerror(APP_NAME, "Не удалось запросить права администратора.")
            return

        try:
            folder, share_name, username, password = self.validate_inputs(
                require_password=True
            )
        except ValueError as exc:
            messagebox.showwarning(APP_NAME, str(exc))
            return

        self.save_current_config()
        make_private = bool(self.make_private_var.get())
        self.status_share_var.set("Общий ресурс: выполняется настройка…")
        self.log(f"Начата настройка папки: {folder}")

        def task() -> None:
            Path(folder).mkdir(parents=True, exist_ok=True)

            result = self.manager.create_or_update_user(username, password)
            if not result.ok:
                raise RuntimeError(
                    "Не удалось создать/обновить пользователя.\n"
                    f"{result.stderr or result.stdout}"
                )
            self.queue_log(f"Пользователь Windows '{username}' создан или обновлён.")

            result = self.manager.grant_ntfs_access(folder, username)
            if not result.ok:
                raise RuntimeError(
                    "Не удалось назначить NTFS-права.\n"
                    f"{result.stderr or result.stdout}"
                )
            self.queue_log("NTFS-права Modify назначены выбранной папке.")

            result = self.manager.create_or_update_share(folder, share_name, username)
            if not result.ok:
                raise RuntimeError(
                    "Не удалось создать SMB-ресурс.\n"
                    f"{result.stderr or result.stdout}"
                )
            self.queue_log(f"SMB-ресурс '{share_name}' создан или обновлён.")

            result = self.manager.enable_smb_firewall_rules()
            if result.ok:
                self.queue_log("Правила брандмауэра SMB включены.")
            else:
                self.queue_log(
                    "Не удалось автоматически включить часть правил брандмауэра: "
                    f"{result.stderr or result.stdout}"
                )

            if make_private:
                result = self.manager.set_active_profiles_private()
                if not result.ok:
                    raise RuntimeError(
                        "Не удалось изменить профиль сети.\n"
                        f"{result.stderr or result.stdout}"
                    )
                self.queue_log("Активная сеть переведена в профиль «Частная».")

            self.ui_queue.put(("clear_password", None))
            self.ui_queue.put(("check", None))
            self.ui_queue.put(
                (
                    "info",
                    "Общий доступ настроен. Данные подключения выведены в журнал.",
                )
            )

        self.run_background(task)

    def repair_share_without_password(self) -> None:
        if not is_windows():
            messagebox.showerror(APP_NAME, "Эта программа предназначена только для Windows.")
            return
        if not is_admin():
            if messagebox.askyesno(
                APP_NAME,
                "Для восстановления SMB-ресурса нужны права администратора.\n\n"
                "Перезапустить программу с запросом UAC?",
            ):
                if relaunch_as_admin():
                    self.root.destroy()
                else:
                    messagebox.showerror(APP_NAME, "Не удалось запросить права администратора.")
            return

        try:
            folder, share_name, username, _ = self.validate_inputs(
                require_password=False
            )
        except ValueError as exc:
            messagebox.showwarning(APP_NAME, str(exc))
            return

        self.save_current_config()
        self.status_share_var.set("Общий ресурс: выполняется восстановление…")
        self.log(
            f"Восстановление SMB-ресурса '{share_name}' для папки: {folder}"
        )

        def task() -> None:
            Path(folder).mkdir(parents=True, exist_ok=True)

            result = self.manager.grant_ntfs_access(folder, username)
            if not result.ok:
                raise RuntimeError(
                    "Не удалось применить NTFS-права.\n"
                    f"{result.stderr or result.stdout}"
                )
            self.queue_log("NTFS-права повторно применены к папке и вложенным элементам.")

            result = self.manager.create_or_update_share(folder, share_name, username)
            if not result.ok:
                raise RuntimeError(
                    "Не удалось создать или восстановить SMB-ресурс.\n"
                    f"{result.stderr or result.stdout}"
                )
            self.queue_log(f"SMB-ресурс '{share_name}' создан или восстановлен.")

            result = self.manager.enable_smb_firewall_rules()
            if result.ok:
                self.queue_log("Правила брандмауэра SMB включены.")
            else:
                self.queue_log(
                    "Не удалось автоматически включить часть правил брандмауэра: "
                    f"{result.stderr or result.stdout}"
                )

            self.ui_queue.put(("check", None))
            self.ui_queue.put(("info", "SMB-ресурс восстановлен. Проверьте подключение на iPhone."))

        self.run_background(task)

    def run_full_check(self) -> None:
        try:
            folder, share_name, username, _ = self.validate_inputs(
                require_password=False
            )
        except ValueError as exc:
            messagebox.showwarning(APP_NAME, str(exc))
            return

        self.save_current_config()
        self.status_share_var.set("Общий ресурс: выполняется проверка…")

        def task() -> None:
            result = self.manager.inspect_status(folder, share_name, username)
            if not result.ok:
                raise RuntimeError(result.stderr or result.stdout)
            data = parse_json_output(result.stdout) or {}
            self.ui_queue.put(("status_data", data))

            if data.get("ShareExists"):
                test_status, test_message = self.manager.unc_read_write_test(share_name)
            else:
                test_status, test_message = (
                    "warning",
                    f"UNC-проверка пропущена: SMB-ресурс '{share_name}' не создан. "
                    "Нажмите «Создать / обновить доступ» или «Починить ресурс без пароля».",
                )
            self.ui_queue.put(("unc_test", (test_status, test_message)))

        self.run_background(task)

    def open_folder(self) -> None:
        folder = self.folder_var.get().strip().strip('"')
        if not folder:
            return
        try:
            Path(folder).mkdir(parents=True, exist_ok=True)
            os.startfile(folder)  # type: ignore[attr-defined]
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def copy_connection_info(self) -> None:
        try:
            folder, share_name, username, _ = self.validate_inputs(
                require_password=False
            )
        except ValueError as exc:
            messagebox.showwarning(APP_NAME, str(exc))
            return

        result = self.manager.inspect_status(folder, share_name, username)
        if not result.ok:
            messagebox.showerror(APP_NAME, result.stderr or result.stdout)
            return

        data = parse_json_output(result.stdout) or {}
        if not data.get("ShareExists"):
            messagebox.showwarning(
                APP_NAME,
                f"SMB-ресурс '{share_name}' ещё не создан.\n\n"
                "Нажмите «Создать / обновить доступ» или "
                "«Починить ресурс без пароля», затем повторите копирование.",
            )
            self.log(f"Данные подключения не скопированы: SMB-ресурс '{share_name}' не создан.")
            return

        ips = self._ensure_list(data.get("IPAddresses"))
        computer = data.get("ComputerName") or get_computer_name()

        lines = [
            "Подключение на iPhone:",
            "Файлы → Обзор → ⋯ → Подключиться к серверу",
            "",
        ]
        for item in ips:
            ip = item.get("IPAddress")
            if ip:
                lines.append(f"smb://{ip}/{share_name}")
        lines += [
            "",
            "Тип входа: Зарегистрированный пользователь",
            f"Имя: {computer}\\{username}",
            "Пароль: пароль, заданный в программе",
        ]

        text = "\n".join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log("Данные подключения скопированы в буфер обмена.")
        messagebox.showinfo(APP_NAME, text)

    def remove_share(self) -> None:
        share_name = sanitize_share_name(self.share_var.get())
        if not share_name:
            return
        if not is_admin():
            messagebox.showwarning(APP_NAME, "Нужны права администратора.")
            return
        if not messagebox.askyesno(
            APP_NAME,
            f"Удалить SMB-ресурс '{share_name}'?\n\n"
            "Сама папка и файлы удалены не будут.",
        ):
            return

        def task() -> None:
            result = self.manager.remove_share(share_name)
            if not result.ok:
                raise RuntimeError(result.stderr or result.stdout)
            self.queue_log(f"SMB-ресурс '{share_name}' удалён.")
            self.ui_queue.put(("check", None))

        self.run_background(task)

    def start_monitor(self) -> None:
        if self.monitor_thread and self.monitor_thread.is_alive():
            return
        self.stop_monitor.clear()
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
        )
        self.monitor_thread.start()

    def _monitor_loop(self) -> None:
        while not self.stop_monitor.wait(3.0):
            try:
                with self.monitor_settings_lock:
                    settings = dict(self.monitor_settings)
                folder = settings["folder"]
                share_name = settings["share_name"]
                username = settings["username"]
                if not folder or not share_name or not username:
                    continue

                status_result = self.manager.inspect_status(folder, share_name, username)
                if status_result.ok:
                    data = parse_json_output(status_result.stdout) or {}
                    self.ui_queue.put(("monitor_status", data))

                adapter_result = self.manager.get_adapter_stats()
                if adapter_result.ok:
                    adapters = self._ensure_list(parse_json_output(adapter_result.stdout))
                    self.ui_queue.put(("adapter_stats", adapters))
            except Exception as exc:
                append_file_log(f"Ошибка мониторинга: {exc}")

    @staticmethod
    def _ensure_list(value: Any) -> list[dict[str, Any]]:
        if value is None:
            return []
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    @staticmethod
    def _format_network_category(value: Any) -> str:
        mapping = {
            "0": "Public",
            "1": "Private",
            "2": "DomainAuthenticated",
            "Public": "Public",
            "Private": "Private",
            "DomainAuthenticated": "DomainAuthenticated",
        }
        return mapping.get(str(value), str(value))

    @staticmethod
    def _format_identity(value: Any) -> str:
        if isinstance(value, dict):
            return str(value.get("Value") or value)
        return str(value)

    def _process_ui_queue(self) -> None:
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()

                if kind == "log":
                    self.log(str(payload))
                elif kind == "error":
                    self.log(f"ОШИБКА: {payload}")
                    self.status_share_var.set("Общий ресурс: ошибка")
                    messagebox.showerror(APP_NAME, str(payload).split("\n\n")[0])
                elif kind == "info":
                    messagebox.showinfo(APP_NAME, str(payload))
                elif kind == "clear_password":
                    self.password_var.set("")
                elif kind == "check":
                    self.run_full_check()
                elif kind == "status_data":
                    self.render_full_status(payload)
                elif kind == "monitor_status":
                    self.render_monitor_status(payload)
                elif kind == "adapter_stats":
                    self.render_adapter_stats(payload)
                elif kind == "unc_test":
                    status, message = payload
                    prefix = {
                        "ok": "OK: ",
                        "warning": "ПРЕДУПРЕЖДЕНИЕ: ",
                        "error": "ОШИБКА: ",
                    }.get(str(status), "")
                    self.log(prefix + message)
        except queue.Empty:
            pass
        finally:
            self.root.after(150, self._process_ui_queue)

    def render_full_status(self, data: dict[str, Any]) -> None:
        share_exists = bool(data.get("ShareExists"))
        share_path = data.get("SharePath")
        folder_exists = bool(data.get("FolderExists"))
        user_exists = bool(data.get("UserExists"))
        user_enabled = bool(data.get("UserEnabled"))
        service = data.get("ServerService")
        port445 = bool(data.get("Port445Listening"))

        if share_exists:
            self.status_share_var.set(
                f"Общий ресурс: доступен ({self.share_var.get()} → {share_path})"
            )
        else:
            self.status_share_var.set(
                "Общий ресурс: не создан — нажмите «Создать / обновить доступ» "
                "или «Починить ресурс без пароля»"
            )

        profiles = self._ensure_list(data.get("Profiles"))
        profile_desc = ", ".join(
            f"{p.get('InterfaceAlias')}: "
            f"{self._format_network_category(p.get('NetworkCategory'))}"
            for p in profiles
        ) or "не определён"
        self.status_network_var.set(
            f"Сеть: {profile_desc}; SMB-служба: {service}; порт 445: "
            f"{'слушает' if port445 else 'не слушает'}"
        )

        self.log("----- Полная проверка -----")
        self.log(f"Папка существует: {'да' if folder_exists else 'нет'}")

        folder_items = self._ensure_list(data.get("FolderItems"))
        folders_count = sum(1 for item in folder_items if item.get("Type") == "Folder")
        files_count = sum(1 for item in folder_items if item.get("Type") == "File")
        if folder_exists:
            if folder_items:
                preview = ", ".join(str(item.get("Name")) for item in folder_items[:12])
                self.log(
                    f"Содержимое папки видно программе: папок {folders_count}, "
                    f"файлов {files_count}. Первые элементы: {preview}"
                )
            else:
                self.log(
                    "Содержимое папки не прочитано или папка пуста. "
                    "Если на iPhone папки не видны, нажмите «Создать / обновить доступ» "
                    "для повторного применения прав ко вложенным папкам."
                )

        diagnostics = data.get("Diagnostics") or []
        if isinstance(diagnostics, str):
            diagnostics = [diagnostics]
        if diagnostics:
            self.log("Диагностика PowerShell:")
            for item in diagnostics:
                self.log(f"  {item}")

        self.log(
            f"Пользователь существует/включён: "
            f"{'да' if user_exists else 'нет'} / {'да' if user_enabled else 'нет'}"
        )
        self.log(f"SMB-ресурс существует: {'да' if share_exists else 'нет'}")
        if not share_exists:
            self.log(
                "SMB-ресурс не создан: iPhone не сможет открыть этот адрес, "
                "а UNC-проверка будет недоступна. Нажмите «Создать / обновить доступ» "
                "или «Починить ресурс без пароля»."
            )
            candidates = self._ensure_list(data.get("ShareCandidatesByPath"))
            if candidates:
                names = ", ".join(str(item.get("Name")) for item in candidates)
                self.log(
                    "Для этой папки уже есть SMB-ресурс с другим именем: "
                    f"{names}. Можно указать одно из этих имён в поле SMB-ресурса."
                )
        self.log(f"Служба LanmanServer: {service}")
        self.log(f"Порт TCP 445: {'слушает' if port445 else 'не слушает'}")
        self.log(f"Сетевые профили: {profile_desc}")

        ips = self._ensure_list(data.get("IPAddresses"))
        if ips and share_exists:
            computer = data.get("ComputerName") or get_computer_name()
            self.log("Данные подключения на iPhone:")
            for item in ips:
                ip = item.get("IPAddress")
                alias = item.get("InterfaceAlias")
                if ip:
                    self.log(f"  smb://{ip}/{self.share_var.get()}  ({alias})")
            self.log(f"  Пользователь: {computer}\\{self.user_var.get()}")
        elif ips:
            self.log(
                "IP-адрес найден, но адрес для iPhone пока не выводится, "
                "потому что SMB-ресурс не создан."
            )
        else:
            self.log("Не найден IPv4-адрес активного адаптера с шлюзом.")

        share_access = self._ensure_list(data.get("ShareAccess"))
        if share_access:
            self.log("Права SMB:")
            for access in share_access:
                self.log(
                    f"  {access.get('AccountName')}: "
                    f"{access.get('AccessControlType')} / {access.get('AccessRight')}"
                )

        acl = data.get("AclEntry")
        if isinstance(acl, dict):
            self.log(
                "NTFS ACL: "
                f"{self._format_identity(acl.get('IdentityReference'))} / "
                f"{acl.get('FileSystemRights')}"
            )
        else:
            self.log("NTFS ACL для выбранного пользователя не найден.")

        self.render_sessions(data)

    def render_monitor_status(self, data: dict[str, Any]) -> None:
        sessions = self._ensure_list(data.get("Sessions"))
        open_files = self._ensure_list(data.get("OpenFiles"))

        if sessions:
            clients = sorted(
                {
                    str(s.get("ClientComputerName") or "?")
                    for s in sessions
                }
            )
            has_tcp_fallback = any(s.get("Source") == "TCP445" for s in sessions)
            suffix = " (TCP 445, без деталей SMB)" if has_tcp_fallback else ""
            self.status_connection_var.set(
                "iPhone/SMB-клиент: подключён — " + ", ".join(clients) + suffix
            )
        else:
            self.status_connection_var.set("iPhone/SMB-клиент: активных сессий нет")

        transfer_messages: list[str] = []
        now = time.time()

        for item in open_files:
            path = str(item.get("Path") or "")
            if not path:
                continue
            try:
                size = os.path.getsize(path) if os.path.isfile(path) else 0
            except OSError:
                size = 0

            previous = self.file_size_history.get(path)
            speed = 0.0
            if previous:
                prev_size, prev_time = previous
                elapsed = max(now - prev_time, 0.001)
                speed = max(0.0, (size - prev_size) / elapsed)
            self.file_size_history[path] = (size, now)

            short_name = Path(path).name or path
            if speed > 1024:
                transfer_messages.append(
                    f"{short_name}: {format_bytes(size)}, +{format_bytes(speed)}/с"
                )
            else:
                transfer_messages.append(f"{short_name}: открыт, {format_bytes(size)}")

        # Очищаем историю давно не открытых файлов.
        active_paths = {str(item.get("Path") or "") for item in open_files}
        self.file_size_history = {
            path: value
            for path, value in self.file_size_history.items()
            if path in active_paths
        }

        if transfer_messages:
            self.status_transfer_var.set("Передача: " + " | ".join(transfer_messages[:2]))
        elif sessions:
            self.status_transfer_var.set("Передача: клиент подключён, активных файлов нет")
        else:
            self.status_transfer_var.set("Передача: активности нет")

        self.render_sessions(data, quiet=True)

    def render_adapter_stats(self, adapters: list[dict[str, Any]]) -> None:
        now = time.time()
        speeds = []

        for item in adapters:
            name = str(item.get("Name") or "адаптер")
            rx = int(item.get("ReceivedBytes") or 0)
            tx = int(item.get("SentBytes") or 0)
            previous = self.last_adapter_sample.get(name)
            self.last_adapter_sample[name] = (rx, tx, now)
            if not previous:
                continue

            prev_rx, prev_tx, prev_time = previous
            elapsed = max(now - prev_time, 0.001)
            rx_speed = max(0.0, (rx - prev_rx) / elapsed)
            tx_speed = max(0.0, (tx - prev_tx) / elapsed)
            speeds.append((name, rx_speed, tx_speed))

        if speeds:
            name, rx_speed, tx_speed = max(
                speeds,
                key=lambda item: item[1] + item[2],
            )
            current = self.status_transfer_var.get()
            suffix = (
                f" | Сеть {name}: ↓ {format_bytes(rx_speed)}/с, "
                f"↑ {format_bytes(tx_speed)}/с"
            )
            # Не накапливаем старые значения скорости.
            base = current.split(" | Сеть ", 1)[0]
            self.status_transfer_var.set(base + suffix)

    def render_sessions(self, data: dict[str, Any], quiet: bool = False) -> None:
        sessions = self._ensure_list(data.get("Sessions"))
        open_files = self._ensure_list(data.get("OpenFiles"))

        diagnostics = data.get("Diagnostics") or []
        if isinstance(diagnostics, str):
            diagnostics = [diagnostics]

        lines = [
            f"Обновлено: {datetime.now().strftime('%H:%M:%S')}",
            "",
            "SMB-СЕССИИ / TCP-ПОДКЛЮЧЕНИЯ",
            "-----------------------------",
        ]

        if diagnostics:
            lines.extend(["Диагностика:"])
            lines.extend(f"  {item}" for item in diagnostics)
            lines.append("")

        folder_items = self._ensure_list(data.get("FolderItems"))
        if folder_items:
            folders_count = sum(1 for item in folder_items if item.get("Type") == "Folder")
            files_count = sum(1 for item in folder_items if item.get("Type") == "File")
            lines.extend(
                [
                    "СОДЕРЖИМОЕ ОБЩЕЙ ПАПКИ",
                    "----------------------",
                    f"Видно программе: папок {folders_count}, файлов {files_count}",
                ]
            )
            for item in folder_items[:25]:
                marker = "[DIR]" if item.get("Type") == "Folder" else "     "
                lines.append(f"{marker} {item.get('Name')}")
            lines.append("")

        if not sessions:
            lines.append("Активных SMB-сессий нет.")
        else:
            for item in sessions:
                lines.extend(
                    [
                        f"Источник: {item.get('Source') or 'SMB'}",
                        f"Клиент: {item.get('ClientComputerName')}",
                        f"Пользователь: {item.get('ClientUserName')}",
                        f"Открыто объектов: {item.get('NumOpens')}",
                        f"SMB: {item.get('Dialect')}; "
                        f"Signed={item.get('Signed')}; "
                        f"Encrypted={item.get('Encrypted')}",
                        f"Длительность: {item.get('SecondsExists')} с",
                        "",
                    ]
                )

        lines.extend(["", "ОТКРЫТЫЕ ПО СЕТИ ФАЙЛЫ", "----------------------"])
        if not open_files:
            lines.append("Открытых SMB-файлов нет.")
        else:
            for item in open_files:
                path = str(item.get("Path") or "")
                size_text = "неизвестно"
                try:
                    if path and os.path.isfile(path):
                        size_text = format_bytes(os.path.getsize(path))
                except OSError:
                    pass
                lines.extend(
                    [
                        f"Путь: {path}",
                        f"Размер сейчас: {size_text}",
                        f"Клиент: {item.get('ClientComputerName')}",
                        f"Пользователь: {item.get('ClientUserName')}",
                        f"Права: {item.get('Permissions')}",
                        "",
                    ]
                )

        self.sessions_text.delete("1.0", END)
        self.sessions_text.insert(END, "\n".join(lines))

        if not quiet and sessions:
            self.log(f"Обнаружено SMB-сессий: {len(sessions)}.")

    def on_close(self) -> None:
        self.stop_monitor.set()
        self.save_current_config()
        self.root.destroy()


def main() -> int:
    ensure_app_dir()

    if not is_windows():
        print("Эта программа предназначена для Windows 10/11.", file=sys.stderr)
        return 1

    # Не повышаем права автоматически без объяснения: GUI сам предложит UAC,
    # когда пользователь нажмёт кнопку настройки.
    root = Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
