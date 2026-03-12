import ipaddress
import json
import subprocess
import sys
from urllib import error as urllib_error
from urllib import request as urllib_request

from .runtime import (
    cleanup_temp_file,
    create_temp_file,
    is_executable_available,
    read_process_output,
    stop_process,
    wait_for_process_startup,
)

DEFAULT_TAILSCALE_FUNNEL_PORT = 8443
TAILSCALE_FUNNEL_PORTS = (443, 8443, 10000)
LOCALHOST = "127.0.0.1"
PUBLIC_DNS_ENDPOINTS = (
    (
        "https://cloudflare-dns.com/dns-query?name={hostname}&type=A",
        {"accept": "application/dns-json"},
    ),
    (
        "https://dns.google/resolve?name={hostname}&type=A",
        {},
    ),
)


class Funnel:
    def __init__(self, args):
        self.args = args
        self.proc = None
        self.log_file = None
        self.endpoint = None
        self.public_ip = None

    def validate(self, error_text):
        if not self.args.tailscale_funnel:
            return True

        if not is_executable_available(self.args.tailscale_bin):
            print(
                error_text(f"Error: tailscale binary not found: {self.args.tailscale_bin}"),
                file=sys.stderr,
            )
            return False

        if self.args.tailscale_funnel_port not in TAILSCALE_FUNNEL_PORTS:
            allowed = ", ".join(str(port) for port in TAILSCALE_FUNNEL_PORTS)
            print(
                error_text(
                    "Error: --tailscale-funnel-port must be one of "
                    f"{allowed}. Tailscale Funnel only exposes those public ports."
                ),
                file=sys.stderr,
            )
            return False

        if not is_executable_available(self.args.openssl_bin):
            print(
                error_text(f"Error: openssl binary not found: {self.args.openssl_bin}"),
                file=sys.stderr,
            )
            return False

        return True

    def prepare(self, error_text):
        if not self.args.tailscale_funnel:
            return True

        server_host = self.infer_server_host(error_text)
        if not server_host:
            return False

        self.args.server_host = server_host
        self.public_ip = self.resolve_public_ip(server_host)
        if self.public_ip:
            return True

        print(
            error_text(
                "Error: could not resolve a public IPv4 address for the "
                "Tailscale Funnel hostname."
            ),
            file=sys.stderr,
        )
        print(
            "Pass --tailscale-public-ip explicitly if public DNS has not propagated yet.",
            file=sys.stderr,
        )
        return False

    def infer_server_host(self, error_text):
        result = subprocess.run(
            [self.args.tailscale_bin, "status", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            output = (result.stdout or "") + (result.stderr or "")
            print(
                error_text("Failed to infer --server-host from Tailscale.\n"),
                file=sys.stderr,
            )
            print(output or "(no output)", file=sys.stderr)
            return None

        try:
            status = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            print(
                error_text(f"Failed to parse Tailscale status output: {exc}"),
                file=sys.stderr,
            )
            return None

        dns_name = ((status.get("Self") or {}).get("DNSName") or "").rstrip(".")
        if dns_name:
            return dns_name

        print(
            error_text("Could not infer a Tailscale DNS name for Funnel."),
            file=sys.stderr,
        )
        return None

    def resolve_public_ip(self, hostname):
        if self.args.tailscale_public_ip:
            return self.args.tailscale_public_ip

        for url_template, headers in PUBLIC_DNS_ENDPOINTS:
            request = urllib_request.Request(
                url_template.format(hostname=hostname),
                headers=headers,
            )
            try:
                with urllib_request.urlopen(request, timeout=5) as response:
                    payload = json.load(response)
            except (OSError, TimeoutError, ValueError, urllib_error.URLError):
                continue

            for answer in payload.get("Answer") or []:
                if answer.get("type") != 1:
                    continue

                candidate = answer.get("data")
                if not candidate:
                    continue

                try:
                    ip = ipaddress.ip_address(candidate)
                except ValueError:
                    continue

                if isinstance(ip, ipaddress.IPv4Address) and ip.is_global:
                    return candidate

        return None

    def client_target(self, gateway_port):
        if self.args.tailscale_funnel:
            return self.args.server_host, self.args.tailscale_funnel_port
        return self.args.server_host, gateway_port

    def proxy_option(self, target_host, target_port):
        if not self.args.tailscale_funnel:
            return None

        connect_host = self.public_ip or target_host
        proxy_cmd = (
            f"{self.args.openssl_bin} s_client -quiet "
            f"-servername {target_host} -connect {connect_host}:{target_port}"
        )
        return f"-oProxyCommand={proxy_cmd}"

    def start(self, gateway_port, *, error_text, startup_wait):
        self.log_file = create_temp_file(
            mode="w+",
            suffix=".log",
            prefix="tailscale-funnel-",
        )

        try:
            self.proc = subprocess.Popen(
                [
                    self.args.tailscale_bin,
                    "funnel",
                    f"--tls-terminated-tcp={self.args.tailscale_funnel_port}",
                    f"tcp://{LOCALHOST}:{gateway_port}",
                ],
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError:
            print(
                error_text(f"Error: tailscale binary not found: {self.args.tailscale_bin}"),
                file=sys.stderr,
            )
            return False
        except OSError as exc:
            print(
                error_text(f"Error starting tailscale funnel: {exc}"),
                file=sys.stderr,
            )
            return False

        self.endpoint = f"tcp://{self.args.server_host}:{self.args.tailscale_funnel_port}"
        if wait_for_process_startup(
            self.proc,
            startup_wait=startup_wait,
            error_label="tailscale funnel",
            log_file=self.log_file,
            error_text=error_text,
        ):
            return True

        self.proc = None
        self.endpoint = None
        return False

    def check(self, error_text):
        proc = self.proc
        if proc is None or proc.poll() is None:
            return None

        returncode = proc.returncode
        self.proc = None
        self.endpoint = None

        if returncode != 0:
            output = read_process_output(self.log_file)
            print(
                error_text("tailscale funnel exited unexpectedly.\n"),
                file=sys.stderr,
            )
            print(output or "(no output)", file=sys.stderr)

        return returncode

    def stop(self, *, force):
        stop_process(self.proc, force=force)
        self.proc = None
        self.endpoint = None

    def cleanup(self):
        self.stop(force=True)
        cleanup_temp_file(self.log_file)
        self.log_file = None
