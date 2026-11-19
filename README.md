# HomePortMap

A real, low-impact TCP inventory tool for a **home network you own/administer or are explicitly authorized to assess**. It checks a fixed set of ten common TCP ports, reports which private IPv4 hosts answered, and sends no application payloads or exploit traffic.

## Guardrails

- Accepts only RFC1918 IPv4 subnets (`10/8`, `172.16/12`, `192.168/16`) no broader than `/24`.
- Requires `--confirm-authorized`.
- Fixed port list, four concurrent connections maximum, short timeout.
- TCP connect checks only; no UDP, banner grabbing, service fingerprinting, brute force, or exploitation.
- Do not run on work, school, shared, or neighbor networks without explicit permission.

## Use

Python 3.9+; standard library only.

```bash
python -m homeportmap.cli 192.168.1.0/24 --confirm-authorized
```

Choose the exact subnet from your router/device settings; do not guess. Results are JSON. A port being open does not by itself mean a vulnerability exists.

## Tests

```bash
python -m unittest discover -s tests -v
```

AI-assisted starter implementation; review and extend before representing the work as your own.
