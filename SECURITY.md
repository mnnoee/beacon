# Security

This document describes what the project is for, what it is not for, and which
risks remain in the code as it stands.

## Supported use

A local network you control, where every device either is yours or has been
allowed on purpose:

- home LAN;
- isolated office or lab network;
- a bench of your own devices.

## Out of scope

- The open internet without a VPN or tunnel on top. Discovery is broadcast UDP
  and assumes a flat, trusted segment.
- Networks where untrusted third-party devices roam. Anyone on such a segment can
  see discovery traffic and attempt to connect.
- Anything with a compliance requirement. This code has not been audited.

## Trust model in one paragraph

A single root CA signs every node certificate. Nodes accept a neighbour only if
its certificate chains to that CA and is not revoked. Discovery packets are
signed with the Ed25519 key stored in the sender's certificate, but a packet from
an unknown node is treated as a *connection request*, not as proof of identity —
real authentication happens in the mTLS handshake. Whoever controls the CA can
therefore mint any identity in the network. The CA key is the crown jewel: it is
stored on disk, optionally encrypted with AES-256-GCM, and not protected by an
HSM.

## Known weaknesses

1. **Revocation depends on connectivity.** CRLs propagate over gossip. A node
   isolated from the network does not learn it was revoked until it reconnects.
   The local cache survives restarts but cannot help an isolated node.
2. **SSH gives a shell as the beacon's user.** Typically root. The guard is the
   allowlist: SSH is off unless `-ssh` is given, and an empty allowlist denies
   everyone but the node itself. Anyone who obtains a server-role certificate
   and is listed can run commands as that user.
3. **No rate limiting on SSH authentication.** There is a connection-count limit
   (`-ssh-max-conns`), but no delay between failed attempts.
4. **Time-based.** Discovery packets are accepted within ±5 minutes. Nodes with
   badly drifting clocks cannot see each other.
5. **No key rotation.** Certificates expire (90 days by default) and can be
   reissued, but there is no automatic rotation and no pinning of the CA
   certificate beyond the local copy.
6. **`window-change` is not forwarded** to the interactive process, so terminal
   resizing does not reach the shell.
7. **Written by AI agents.** The code is reviewed by a human, not by a
   cryptographic audit. Assume the usual "good for a well-understood network"
   bar, not more.

## Reporting a problem

Open an issue. For anything that looks like a vulnerability, please describe
reproduction steps rather than a theoretical concern — this is a small project
and concrete reports get fixed.