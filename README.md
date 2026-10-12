# Network Beacons

> **This project was built with AI agents.** Practically all code, tests and
> documentation were written by AI agents (OpenCode/Claude) under the direction
> of [@mnnoee](https://github.com/mnnoee). A human made the architectural
> decisions, tested the result on real devices and owns everything that is here.
> Keep in mind: the code was written fast and reviewed by a person, not by a
> formal audit.

Device discovery on a local network with encrypted peer communication and
allowlisted SSH access. One binary, no runtime dependencies.

```
beacon node  ──UDP broadcast──►  beacon node
     │                              │
     └────── mTLS + cert-share ─────┘   revocations travel the same channel
```

## What it does

Devices on the same network find each other over UDP broadcast and authenticate
each other with mutual TLS against a shared root certificate. After that every
node knows its neighbours' certificates, can reach them by name, and exchanges
certificate revocation updates.

- **No DNS, no servers, no cloud.** Everything stays inside your network.
- **Revocation actually works.** A revoked node is rejected by mTLS and SSH, and
  neighbours learn about it without asking the CA machine.
- **SSH by name:** `beacon ssh beacon-nas uptime` resolves the name through the
  same discovery mechanism.
- **A terminal monitor:** neighbours, addresses, ping, status.

## Why you might want it

A network of home or office devices — routers, NAS boxes, Raspberry Pis, old
phones — where the usual choice is between "let everyone in over SSH" and "let
no one in". Here a node admits only those an administrator issued a certificate
to, and revocation works without rebooting anything or hand-editing access.

Typical uses: reaching a NAS when the router has no usable SSH; a network of
five to twenty devices where you would rather not touch sshd on each one, nor
share one password; experimenting with cryptography and distributed systems —
the project is small and fits in one Go file.

## ⚠️ Where it works, and where it does not

**Local or untrusted networks only — and not every one of them.**

| Fine | Not fine |
|------|----------|
| Home LAN, your own subnet | The open internet without a VPN or tunnel on top |
| Isolated office or country-house network | Any network where you do not control who joins |
| Lab bench, pet project | Networks with foreign devices and no isolation |

Why:

- **Discovery is broadcast.** Anyone on your network can see the beacon packets.
  On its own that reveals little (packets are signed and verified), but it is
  worth knowing what is visible.
- **Losing the CA machine means losing the network.** The CA key is not in an
  HSM; it lives on disk (encrypted with AES-256-GCM if you set a passphrase —
  but then you have to store that passphrase somewhere too).
- **Revocation needs a path.** Nodes exchange CRLs over gossip; a node cut off
  from the network never learns it was revoked.
- **Clocks matter.** Node clocks must agree within 5 minutes.
- **MITM protection only covers your network.** In a network with an active
  observer you do not control, the "we trust only what our CA issued" model does
  not hold: whoever can substitute a certificate at issuance time owns the
  network.

This project has not been audited and is not positioned as a production-ready
solution. It is a tool for your own network and a playground for experiments.

## Quick start

Requires Go 1.26+.

```bash
git clone https://github.com/mnnoee/beacon.git
cd beacon
go build -o beacon .
```

### On the CA machine

```bash
./beacon ca generate-ca -dir ./data                          # CA key and certificate
./beacon ca provision-beacon -dir ./data nas                 # a network participant
./beacon ca provision-beacon -dir ./data -role server nas    # a node that serves SSH
```

Only nodes you will SSH *from* need the `server` role: SSH access is granted to
server-role certificates and to nothing else.

### On a node

```bash
# copy the node files and the CA certificate to the device
scp -r ./data/beacon-nas nas:~/beacon-data/
scp ./data/ca/ca-cert.pem        nas:~/beacon-data/ca/

./beacon beacon -dir ~/beacon-data -name beacon-nas \
  -broadcast 192.168.1.255 -ssh -ssh-allow beacon-nas,beacon-other
```

The SSH server is **disabled by default**, and an empty `-ssh-allow` denies
everyone except the node itself.

### From there

```bash
# who is connected to whom
cat ~/beacon-data/state.json

# reach a neighbour by name
./beacon ssh -dir ~/beacon-data -name beacon-nas \
  -disc-port 1984 -broadcast 192.168.1.255 beacon-other 'uptime'

# monitor (separate process, reads state.json)
./beacon monitor -dir ~/beacon-data -name beacon-nas -tls-port 1985

# revoke a node: signed by the CA, spread over gossip
./beacon ca revoke-beacon -dir ./data -node beacon-other
```

Details: [docs/USAGE.md](docs/USAGE.md) for commands and flags,
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how trust is built.

## How it works, briefly

| Layer | Choice |
|-------|--------|
| Discovery | UDP broadcast, every packet signed with the node's Ed25519 key |
| Identity | `nodeID = sha256(Ed25519 key)[:16]`, the key lives in the certificate SAN |
| Transport | Mutual TLS, client certificate mandatory |
| Certificate exchange | `PktCertShare` over the established mTLS channel |
| Revocation | CRL on `crypto/x509`, gossiped, cached locally on nodes without the CA key |
| Keys at rest | Mode 0600, optionally AES-256-GCM with a passphrase from `BEACON_PASSPHRASE` |

Protocol version 2. For the trust model and the threat list, see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```bash
go test -race ./...      # 94 tests, ~62% coverage
go test -cover ./...
gofmt -l . && go vet ./...
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) checks formatting,
runs `vet` and the race-enabled test suite, and builds `linux/amd64`,
`linux/arm64` and `linux/mipsle` (routers).

The work plan and its status: [docs/ROADMAP.md](docs/ROADMAP.md).

## Documentation

| File | About |
|------|-------|
| [README.md](README.md) | this file |
| [README.ru.md](README.ru.md) | the same in Russian |
| [docs/USAGE.md](docs/USAGE.md) | commands, flags, troubleshooting |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | architecture, protocol, trust model (Russian) |
| [docs/ROADMAP.md](docs/ROADMAP.md) | the improvement plan and its status (Russian) |
| [SECURITY.md](SECURITY.md) | scope and known risks |
| [CONTRIBUTING.md](CONTRIBUTING.md) | how to contribute (note: AI agents did the writing) |

## License

MIT — see [LICENSE](LICENSE). Use it, change it, take it into your own projects;
attribution is required.

Author: [@mnnoee](https://github.com/mnnoee)