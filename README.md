# frsh

`frsh` (Fast Reverse SHell) is a small CLI for creating ephemeral SSH tunnels over a temporary `frps` gateway. It is useful when you want to connect to a machine behind NAT or a firewall without keeping long-lived SSH config around.

## Install

Clone the repo and install it as a local tool:

```bash
uv tool install .
```

You can also run it directly from the checkout:

```bash
uv run frsh --help
```

## Usage

Start a tunnel with:

```bash
frsh --server-host your-server.example.com
```

If you have Tailscale installed, you can automatically create a Funnel:

```bash
frsh --tailscale-funnel
```
