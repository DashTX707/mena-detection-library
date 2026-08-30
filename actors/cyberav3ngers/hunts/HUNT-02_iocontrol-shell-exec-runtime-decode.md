# Hunt: IOCONTROL arbitrary-command execution & runtime config decode on OT gateways

- **Hypothesis:** If IOCONTROL is live on a managed Linux OT/IoT device, then its "Execute command" module should manifest as a non-shell IoT service binary (e.g. `/usr/bin/iocontrol`) spawning `/bin/sh -c`/`system()` children to run arbitrary OS commands and publish the output back to C2 — an unexpected parent→child relationship that a normal fixed-function appliance never produces. In parallel, because the implant stores its C2 host, port and MQTT topics as AES-256-CBC encrypted, length-prefixed blobs on disk and decrypts them in memory immediately before use, on the gateways where we *can* collect files we should find high-entropy opaque config artifacts alongside that binary, with the decode itself leaving little on-disk trace (so the tell is the encrypted-at-rest artifact + the runtime shell fan-out, not the decrypt event).
- **ATT&CK:**
  - T1059.004 — Command and Scripting Interpreter: Unix Shell (execution)
  - T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File (defense-evasion / "stealth")
  - T1140 — Deobfuscate/Decode Files or Information (defense-evasion / "stealth")

- **Actor procedure:** IOCONTROL exposes an "Execute command" module that runs arbitrary OS commands via `system()` and publishes results to C2. Its configuration (C2 hostname, port, MQTT topics) is stored as AES-256-CBC encrypted, length-prefixed blobs on disk; at runtime it derives the AES key/IV as the SHA-256 of an embedded victim GUID (used as a hex string), pulls it from environment variables, and decrypts each entry in memory immediately before use.
- **Why a hunt, not a rule:** The decrypt happens in memory on a constrained device and leaves essentially no log — there is nothing to alert on for the decode itself, so this cannot be a rule. Encrypted-at-rest config is by design opaque to log-based detection; its value is in *entropy/sample analysis* of files recovered from a suspect device, which is investigative, not a streaming rule. The shell-exec side has real base-rate noise: many gateways legitimately shell out for health checks and vendor scripts, so "binary spawned `sh`" alone over-fires. The discriminating, robust signal is the *relationship* — a specific IoT service binary that has no legitimate reason to launch interactive shell commands doing so, especially with argv that reads back device state or network info for exfil to C2. Stacking that unexpected parent→child with a co-located high-entropy config blob on the same device is what makes a finding; a per-binary allowlist of expected children could later be handed to detection-engineering.

## Data sources required

- Managed-gateway auditd `execve` records (parent `process.executable` → child `sh`/`bash`/`busybox`) or EDR process lineage
- File collection from suspect gateways + entropy scoring of config-like artifacts near the implant binary
- Process-to-network correlation (the shelling binary also holds the MQTT/TLS socket — ties to HUNT-03)
- Environment-variable capture where available (key/IV derived from a GUID env var)
- Golden-image process-lineage baseline per device model (what each service binary is *expected* to spawn)

## Query starting point

Platform: `Linux auditd (SOF-ELK / Elastic) — non-shell service binary spawning a shell + high-entropy config artifact`

```elasticsearch
# (a) unexpected shell fan-out: an IoT service binary spawning sh/bash
event.module:auditd and auditd.data.syscall:execve
  and process.parent.executable:("/usr/bin/*" or "/usr/sbin/*" or "/opt/*")
  and process.executable:("/bin/sh" or "/bin/bash" or "/bin/busybox" or "/usr/bin/sh")
  and not process.parent.executable in (per_model_expected_shell_parents)  # baseline exclude
| stats children=count(), argv=values(process.command_line),
        first=min(@timestamp) by host.name, process.parent.executable
| sort children desc
# flag parents whose argv reads device/network state (ifconfig, cat /proc, mosquitto_pub-like)

# (b) entropy triage of files near a suspect binary (offline, on collected samples):
#   for f in <collected>: shannon_entropy(f) > 7.5 and file(f)=="data"
#   and length-prefixed structure  -> candidate IOCONTROL encrypted config
#   pivot: attempt decrypt with AES-256-CBC key = sha256(victim_GUID) as hex string
```

## Triage guidance

- **Likely malicious:** a fixed-function IoT/OT service binary spawning `/bin/sh -c` with argv that enumerates device or network state, reads `/proc`, or pipes output toward a network utility; a high-entropy (>7.5), length-prefixed opaque config file sitting next to a suspect `/usr/bin` binary that has no vendor package provenance; the shelling binary being the same process that holds an outbound 8883 socket.
- **Likely benign / expected:** vendor management agents, cron-driven health checks, and busybox-based init legitimately spawn shells — baseline the expected shell-parents per model and suppress them. Genuinely encrypted vendor config (VPN secrets, licensing blobs) is also high-entropy — provenance (owned by a signed package, expected path) distinguishes it from an unmanaged implant artifact.
- **Pivot next:** if confirmed, collect the encrypted config and attempt the documented key derivation (SHA-256 of the victim GUID as a hex string) to recover C2 parameters, then feed the recovered broker host/topics into HUNT-03 and the domain into HUNT-05. Live arbitrary command execution on OT is an active incident → escalate to incident-response-coordinator and image before remediation (self-delete risk, T1070.004).

## References

- https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
- https://attack.mitre.org/techniques/T1059/004/
- https://attack.mitre.org/techniques/T1027/013/
- https://attack.mitre.org/techniques/T1140/
