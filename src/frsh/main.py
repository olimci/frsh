import argparse
import atexit
import os
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from .funnel import DEFAULT_TAILSCALE_FUNNEL_PORT, Funnel
from .runtime import (
    cleanup_temp_file,
    create_temp_file,
    is_executable_available,
    stop_process,
    wait_for_process_startup,
    which,
)

CONNECT_LOG_PATTERNS = (
    "client login info",
    "login to server success",
    "new proxy",
    "proxy added:",
)

DISCONNECT_LOG_PATTERNS = (
    "control is closed",
    "proxy closing",
    "close proxy",
)

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"

LOCALHOST = "127.0.0.1"
UNSPECIFIED_HOSTS = {"", "0.0.0.0", "::"}

DEFAULT_LOCAL_PORT = 22
DEFAULT_REMOTE_PORT = 8080

DEFAULT_STARTUP_WAIT = 1.0
DEFAULT_AUTO_SSH_CONNECT_TIMEOUT = 2
DEFAULT_AUTO_SSH_CONNECTION_ATTEMPTS = 30

STOP_GRACE_PERIOD = 5.0
CONNECTION_POLL_INTERVAL = 0.5
FRPS_PROXY_USER = "v0"

CLIPBOARD_COMMANDS = {
    "pbcopy": (),
    "wl-copy": (),
    "xclip": ("-selection", "clipboard"),
    "xsel": ("--clipboard", "--input"),
}


def find_clipboard_bin():
    for binary in CLIPBOARD_COMMANDS:
        path = which(binary)
        if path:
            return path
    return None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Launch a temporary frps SSH tunnel gateway and print a client command."
    )
    parser.add_argument(
        "--server-host",
        help="Public hostname or IP that the client will connect to",
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=DEFAULT_LOCAL_PORT,
        help="Local port on the client machine to expose",
    )
    parser.add_argument(
        "--remote-port",
        type=int,
        default=DEFAULT_REMOTE_PORT,
        help="Remote port to expose through frp",
    )
    parser.add_argument(
        "--gateway-port",
        type=int,
        default=0,
        help="Port for the frps SSH gateway. Defaults to an automatically chosen free port.",
    )
    parser.add_argument(
        "--frps-bin",
        default="frps",
        help="Path to the frps binary",
    )
    parser.add_argument(
        "--bind-addr",
        default="",
        help="Optional bind address for frps",
    )
    parser.add_argument(
        "--proxy-bind-addr",
        default=LOCALHOST,
        help="Bind address for the reverse proxy port exposed on the server",
    )
    parser.add_argument(
        "-a",
        "--auto-ssh",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Automatically open an SSH session to the client when it connects",
    )
    parser.add_argument(
        "-u",
        "--client-user",
        default=os.environ.get("USER", "root"),
        help="Username to use for the automatic SSH session",
    )
    parser.add_argument(
        "--ssh-bin",
        default="ssh",
        help="Path to the ssh binary used for the automatic SSH session",
    )
    parser.add_argument(
        "--openssl-bin",
        default="openssl",
        help="Path to the openssl binary used for the Funnel TLS proxy command",
    )
    parser.add_argument(
        "--auto-ssh-connect-timeout",
        type=int,
        default=DEFAULT_AUTO_SSH_CONNECT_TIMEOUT,
        help="SSH connection timeout, in seconds, for each automatic SSH attempt",
    )
    parser.add_argument(
        "--auto-ssh-connection-attempts",
        type=int,
        default=DEFAULT_AUTO_SSH_CONNECTION_ATTEMPTS,
        help="How many times automatic SSH should retry the initial connection",
    )
    parser.add_argument(
        "-t",
        "--tailscale-funnel",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Expose the temporary SSH gateway through Tailscale Funnel",
    )
    parser.add_argument(
        "--tailscale-bin",
        default="tailscale",
        help="Path to the tailscale binary used for Funnel",
    )
    parser.add_argument(
        "--tailscale-funnel-port",
        type=int,
        default=0,
        help=f"Public Tailscale Funnel port. Defaults to {DEFAULT_TAILSCALE_FUNNEL_PORT}.",
    )
    parser.add_argument(
        "--tailscale-public-ip",
        help="Optional public IPv4 address to use for the Funnel TLS connection",
    )
    parser.add_argument(
        "-c",
        "--copy",
        action="store_true",
        help="Copy the generated client command to the clipboard",
    )
    parser.add_argument(
        "--startup-wait",
        type=float,
        default=DEFAULT_STARTUP_WAIT,
        help="Seconds to wait before checking whether frps started successfully",
    )
    args = parser.parse_args(argv)
    if args.tailscale_funnel_port == 0:
        args.tailscale_funnel_port = (
            DEFAULT_TAILSCALE_FUNNEL_PORT if args.tailscale_funnel else args.remote_port
        )
    return args


class Tunnel:
    def __init__(self, args):
        self.args = args
        self.frps_proc = None
        self.ssh_proc = None
        self.cfg_file = None
        self.log_file = None
        self.cleaned_up = False
        self.stop_requested = False
        self.stop_deadline = None
        self.log_offset = 0
        self.client_connected = False
        self.auto_ssh_attempted = False
        self.last_connection_poll = 0.0
        self.ssh_started_at = None
        self.lsof_bin = which("lsof")
        self.clipboard_bin = find_clipboard_bin()
        self.use_color = (
            sys.stdout.isatty()
            and os.environ.get("TERM") not in (None, "", "dumb")
            and "NO_COLOR" not in os.environ
        )
        self.funnel = Funnel(args)

    def find_free_port(self, host=LOCALHOST):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            sock.listen(1)
            return int(sock.getsockname()[1])

    def build_config(self, token, bind_port, gateway_port):
        lines = [
            f"bindPort = {bind_port}",
            f'proxyBindAddr = "{self.args.proxy_bind_addr}"',
            f"sshTunnelGateway.bindPort = {gateway_port}",
            f'auth.token = "{token}"',
        ]
        if self.args.bind_addr:
            lines.insert(0, f'bindAddr = "{self.args.bind_addr}"')
        return "\n".join(lines) + "\n"

    def get_auto_ssh_host(self):
        host = self.args.proxy_bind_addr.strip()
        if host in UNSPECIFIED_HOSTS:
            return LOCALHOST
        return host

    def build_client_cmd(self, token, gateway_port):
        target_host, target_port = self.funnel.client_target(gateway_port)
        cmd = [
            "ssh",
            "-oStrictHostKeyChecking=no",
            "-oUserKnownHostsFile=/dev/null",
        ]
        proxy_option = self.funnel.proxy_option(target_host, target_port)
        if proxy_option:
            cmd.append(proxy_option)

        cmd.extend(
            [
                f"-p{target_port}",
                "-R",
                f":{self.args.remote_port}:{LOCALHOST}:{self.args.local_port}",
                f"{FRPS_PROXY_USER}@{target_host}",
                "tcp",
                f"--remote_port={self.args.remote_port}",
                f"--token={token}",
            ]
        )
        return shlex.join(cmd)

    def style(self, text, *codes):
        if not self.use_color or not codes:
            return text
        return "".join(codes) + text + ANSI_RESET

    def label(self, text):
        return self.style(text, ANSI_BOLD, ANSI_CYAN)

    def value(self, text):
        return self.style(text, ANSI_GREEN)

    def muted(self, text):
        return self.style(text, ANSI_DIM)

    def warn(self, text):
        return self.style(text, ANSI_YELLOW)

    def error_text(self, text):
        return self.style(text, ANSI_RED)

    def require_binary(self, binary, label):
        if is_executable_available(binary):
            return True

        print(
            self.error_text(f"Error: {label} binary not found: {binary}"),
            file=sys.stderr,
        )
        return False

    def copy_cmd_to_clipboard(self, cmd):
        if self.clipboard_bin is None:
            return False

        binary_name = Path(self.clipboard_bin).name
        copy_cmd = [self.clipboard_bin, *CLIPBOARD_COMMANDS.get(binary_name, ())]
        result = subprocess.run(
            copy_cmd,
            input=cmd,
            text=True,
            capture_output=True,
            check=False,
        )
        return result.returncode == 0

    def cleanup(self):
        if self.cleaned_up:
            return
        self.cleaned_up = True

        self.stop_ssh_session(force=True)
        self.funnel.cleanup()
        stop_process(self.frps_proc, force=True)
        self.frps_proc = None

        cleanup_temp_file(self.cfg_file)
        cleanup_temp_file(self.log_file)
        self.cfg_file = None
        self.log_file = None

    def request_stop(self, force=False):
        self.stop_ssh_session(force=force)
        self.funnel.stop(force=force)

        proc = self.frps_proc
        if proc is None or proc.poll() is not None:
            return

        try:
            if force:
                proc.kill()
                self.stop_deadline = None
                return

            if not self.stop_requested:
                self.stop_requested = True
                self.stop_deadline = time.monotonic() + STOP_GRACE_PERIOD
                proc.terminate()
        except ProcessLookupError:
            pass

    def install_signal_handlers(self):
        def handler(signum, _frame):
            ssh_proc = self.ssh_proc
            if (
                signum == signal.SIGINT
                and ssh_proc is not None
                and ssh_proc.poll() is None
                and not self.stop_requested
            ):
                return

            if self.stop_requested:
                self.request_stop(force=True)
                return
            self.request_stop()

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def stop_ssh_session(self, force=False):
        stop_process(self.ssh_proc, force=force)
        self.ssh_proc = None
        self.ssh_started_at = None

    def start_ssh_session(self):
        try:
            self.ssh_proc = subprocess.Popen(
                [
                    self.args.ssh_bin,
                    "-o",
                    f"ConnectTimeout={self.args.auto_ssh_connect_timeout}",
                    "-o",
                    f"ConnectionAttempts={self.args.auto_ssh_connection_attempts}",
                    "-tt",
                    "-p",
                    str(self.args.remote_port),
                    f"{self.args.client_user}@{self.get_auto_ssh_host()}",
                ]
            )
            self.ssh_started_at = time.monotonic()
        except FileNotFoundError:
            print(
                self.error_text(f"Error: ssh binary not found: {self.args.ssh_bin}"),
                file=sys.stderr,
            )
        except OSError as exc:
            print(f"Error starting ssh session: {exc}", file=sys.stderr)

    def remote_port_ready(self):
        try:
            with socket.create_connection(
                (self.get_auto_ssh_host(), self.args.remote_port),
                timeout=0.5,
            ):
                return True
        except OSError:
            return False

    def log_shows_connected(self):
        if self.log_file is None:
            return None

        self.log_file.seek(self.log_offset)
        lines = self.log_file.readlines()
        self.log_offset = self.log_file.tell()

        found_signal = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            lower = line.lower()
            if any(pattern in lower for pattern in CONNECT_LOG_PATTERNS):
                found_signal = True
            if any(pattern in lower for pattern in DISCONNECT_LOG_PATTERNS):
                return False
        if found_signal:
            return True
        return None

    def has_connected_client(self, gateway_port):
        if self.lsof_bin is None:
            return self.log_shows_connected()

        now = time.monotonic()
        if now - self.last_connection_poll < CONNECTION_POLL_INTERVAL:
            return None
        self.last_connection_poll = now

        result = subprocess.run(
            [
                self.lsof_bin,
                "-nP",
                f"-iTCP:{gateway_port}",
                "-sTCP:ESTABLISHED",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in (0, 1):
            return None
        return bool(result.stdout.strip())

    def emit_connection_events(self, gateway_port):
        connected = self.has_connected_client(gateway_port)
        if connected is None or connected == self.client_connected:
            return

        self.client_connected = connected
        if connected:
            self.auto_ssh_attempted = False
            return

        self.stop_ssh_session()
        self.auto_ssh_attempted = False

    def update_auto_ssh(self):
        proc = self.ssh_proc
        if proc is not None and proc.poll() is not None:
            runtime = None
            if self.ssh_started_at is not None:
                runtime = time.monotonic() - self.ssh_started_at
            returncode = proc.returncode
            self.ssh_proc = None
            self.ssh_started_at = None

            if (
                self.client_connected
                and returncode != 0
                and runtime is not None
                and runtime < STOP_GRACE_PERIOD
                and not self.remote_port_ready()
            ):
                self.auto_ssh_attempted = False

        if not self.args.auto_ssh or not self.client_connected or self.auto_ssh_attempted:
            return
        if not self.remote_port_ready():
            return

        self.auto_ssh_attempted = True
        self.start_ssh_session()

    def validate_args(self):
        if not self.funnel.validate(self.error_text):
            return False
        if not self.require_binary(self.args.frps_bin, "frps"):
            return False
        if self.args.auto_ssh and not self.require_binary(self.args.ssh_bin, "ssh"):
            return False
        return True

    def ensure_server_host(self):
        if not self.funnel.prepare(self.error_text):
            return False
        if self.args.server_host:
            return True

        print(
            self.error_text("Error: --server-host is required unless it can be inferred."),
            file=sys.stderr,
        )
        return False

    def allocate_ports(self):
        bind_host = self.args.bind_addr or "0.0.0.0"
        gateway_port = self.args.gateway_port

        bind_port = self.find_free_port(bind_host)
        while bind_port == gateway_port:
            bind_port = self.find_free_port(bind_host)

        if gateway_port == 0:
            gateway_port = bind_port
            while gateway_port == bind_port:
                gateway_port = self.find_free_port(bind_host)

        return bind_port, gateway_port

    def start_frps(self, config):
        self.cfg_file = create_temp_file(
            mode="w",
            suffix=".toml",
            prefix="frps-",
        )
        self.cfg_file.write(config)
        self.cfg_file.flush()

        self.log_file = create_temp_file(
            mode="w+",
            suffix=".log",
            prefix="frps-",
        )

        self.frps_proc = subprocess.Popen(
            [self.args.frps_bin, "-c", self.cfg_file.name],
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return wait_for_process_startup(
            self.frps_proc,
            startup_wait=self.args.startup_wait,
            error_label="frps",
            log_file=self.log_file,
            error_text=self.error_text,
        )

    def print_launch_summary(self, client_cmd, gateway_port):
        client_host, client_port = self.funnel.client_target(gateway_port)
        proxy_host = self.args.proxy_bind_addr.strip() or LOCALHOST

        print(f"{self.label('gateway:')} {self.value(f'{client_host}:{client_port}')}")
        print(f"{self.label('proxy:')}   {self.value(f'{proxy_host}:{self.args.remote_port}')}")

        if self.args.auto_ssh:
            print(
                f"{self.label('shell:')}   "
                f"{self.value(f'{self.args.client_user}@{self.get_auto_ssh_host()}')}"
            )

        if self.args.tailscale_funnel:
            funnel_target = (
                self.value(self.funnel.endpoint)
                if self.funnel.endpoint
                else self.muted(
                    f"tcp://<tailscale-host>:{self.args.tailscale_funnel_port}"
                )
            )
            print(f"{self.label('funnel:')} {funnel_target}")

            if self.funnel.public_ip:
                print(
                    self.muted(
                        f"client TLS target resolves via public IP {self.funnel.public_ip}."
                    )
                )
            print(
                self.muted(
                    f"client command uses {self.args.openssl_bin} to wrap SSH in TLS for Funnel."
                )
            )
            print(
                self.muted(
                    "public funnel DNS can take a few minutes to propagate after enabling."
                )
            )

        print()
        print(self.label("on the client, run:"))
        print(self.style(client_cmd, ANSI_BOLD))
        print()

        if self.args.copy and self.copy_cmd_to_clipboard(client_cmd):
            print(self.warn("copied command to clipboard"))
            print()

        print(self.muted("press Ctrl+C to close."))

    def run_event_loop(self, gateway_port):
        assert self.frps_proc is not None

        while True:
            try:
                returncode = self.frps_proc.wait(timeout=0.2)
                if self.stop_requested:
                    return 0
                return returncode
            except subprocess.TimeoutExpired:
                self.emit_connection_events(gateway_port)
                self.update_auto_ssh()
                funnel_returncode = self.funnel.check(self.error_text)
                if funnel_returncode is not None and not self.stop_requested:
                    return funnel_returncode
                if (
                    self.stop_deadline is not None
                    and time.monotonic() >= self.stop_deadline
                ):
                    self.request_stop(force=True)

    def start(self):
        if not self.validate_args():
            return 1
        if not self.ensure_server_host():
            return 1

        token = secrets.token_hex(24)
        bind_port, gateway_port = self.allocate_ports()
        config = self.build_config(token, bind_port, gateway_port)

        try:
            if not self.start_frps(config):
                return int(self.frps_proc.returncode or 1) if self.frps_proc else 1

            if self.args.tailscale_funnel and not self.funnel.start(
                gateway_port,
                error_text=self.error_text,
                startup_wait=self.args.startup_wait,
            ):
                return 1

            client_cmd = self.build_client_cmd(token, gateway_port)
            self.print_launch_summary(client_cmd, gateway_port)
            return self.run_event_loop(gateway_port)
        finally:
            self.cleanup()


def main(argv=None):
    launcher = Tunnel(parse_args(argv))
    atexit.register(launcher.cleanup)
    launcher.install_signal_handlers()
    return launcher.start()


if __name__ == "__main__":
    sys.exit(main())
