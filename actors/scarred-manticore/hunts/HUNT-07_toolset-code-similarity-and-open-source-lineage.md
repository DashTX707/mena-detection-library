# Hunt: Scarred Manticore toolset attribution — code-similarity across LIONTAIL/LIONHEAD/FOXSHELL/SDD and the customized Tunna/Donut open-source lineage

- **Hypothesis:** If a suspicious server-side sample is Scarred Manticore's, then — even with a fresh hash and heavy obfuscation — it will retain **development fingerprints the actor cannot cheaply remove**: shared XOR/Base64 routines, heartbeat/marker strings, and named-pipe/URL-prefix conventions reused across the LIONTAIL loader, LIONHEAD forwarder, FOXSHELL web shell, and SDD backdoor; plus structural inheritance from the open-source tools they built on — a `Tunna v1.1g` HTTP-tunnel skeleton extended with XOR encryption (the FOXSHELL lineage) and Donut-generated position-independent shellcode that loads .NET from memory (the WINTAPIX loader). This is a *retro-hunt / triage* hypothesis: cluster your unknown server-side samples against these signatures rather than watching a live host log.
- **ATT&CK:**
  - T1587.001 — Develop Capabilities: Malware (resource-development) — in-house, iteratively-refined toolset (LIONTAIL + web-shell/named-pipe variants, LIONHEAD, FOXSHELL family, SDD .NET backdoor) tied together by shared code
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — adoption + customization of open-source offensive tooling: **Tunna** (HTTP-tunnelling web shell → FOXSHELL origin, customized to "Tunna v1.1g" + added XOR) and **Donut** (shellcode generation for the WINTAPIX driver's in-memory .NET loading)
- **Actor procedure:** These are off-victim activities — capability *development* and *acquisition* happen on the actor's own infrastructure and are never observable in defender host/network logs. They become useful to the defender only as **attribution and detection-content signals**: shared code and open-source lineage let you (a) confirm a new, unattributed server implant belongs to this cluster, and (b) mine durable behavioral/YARA signatures from the shared building blocks (the XOR-with-first-byte-then-Base64 encoding, fixed heartbeat markers, the Tunna-derived request structure) that survive rebuilds better than any single hash.
- **Why a hunt, not a rule:** you cannot alert on an adversary compiling malware on their own machines (Level 0 for host detection). The value is realized through *sample triage and code-similarity clustering* — analyst work over a malware corpus, not a SIEM query. A single YARA hash-rule is brittle (dies on the next build); the durable discriminators (Summiting Level 2–3) are the *shared implementation details* — the encryption constants, the marker strings, the Tunna/Donut structural DNA — that the actor reuses across the toolset because rewriting them for every sample is expensive. Those clustered signatures then graft back onto the live hunts (HUNT-01/03/04) and onto detection-engineering as durable analytics.

## Data sources required

- A malware/sample repository for the environment (EDR quarantine, sandbox submissions, IR-collected server samples) — this hunt operates over files, not endpoint telemetry
- YARA (with retro-hunt over historical samples) and a diffing/similarity toolset — BinDiff, ssdeep/TLSH fuzzy hashing, and .NET decompilation (dnSpy/ILSpy) for the managed FOXSHELL/SDD components
- Reference material: the open-source **Tunna** and **Donut** projects (to diff structural inheritance), and the Check Point report's technical appendix for the shared markers/constants
- (Optional) VirusTotal / Malpedia access for external corroboration and pivoting on shared imphash/strings

## Query starting point

Platform: `YARA + procedure` (this is triage, not a log search)

```yara
rule scarred_manticore_shared_toolmarks
{
    meta:
        author = "mena-detection-library"
        description = "Heuristic: shared code-marks across LIONTAIL/LIONHEAD/FOXSHELL/SDD and Tunna-derived web shells. Triage/attribution aid — verify hits, tune constants to the Check Point appendix before any blocking use."
        reference = "https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/"
        source = "Scarred Manticore (Storm-0861)"
    strings:
        $tunna1 = "Tunna" ascii wide nocase
        $tunna2 = "1.1g" ascii wide
        // NOTE: replace the placeholders below with the exact heartbeat / marker
        // strings and XOR constants from the report appendix before use.
        $mark1 = "SDD" ascii wide
        $ews1  = "/ews/exchanges/" ascii wide nocase
        $ews2  = "/autodiscover/autodiscovers/" ascii wide nocase
        $httpsys = "HttpReceiveHttpRequest" ascii wide   // HTTP.sys / passive-listener API usage
    condition:
        // web-shell / managed component with Tunna lineage OR
        // passive-listener API marks + an actor-specific marker
        (uint16(0) == 0x5A4D or $ews1 or $ews2) and
        ( (any of ($tunna*)) or ($httpsys and any of ($mark1,$ews1,$ews2)) )
}
```

Procedure: retro-hunt this rule (and per-family variants) across the sample corpus; for hits, TLSH/ssdeep-cluster them and BinDiff/decompile to confirm shared routines (XOR-then-Base64, heartbeat markers) and Tunna/Donut inheritance. Promote only *verified* clusters.

## Triage guidance

- **Likely malicious / same-cluster:** a server-side web shell or .NET assembly that carries the customized Tunna "1.1g"+XOR structure, reuses the shared heartbeat/marker strings or encryption constants seen across LIONTAIL/LIONHEAD/FOXSHELL/SDD, or shows Donut-style in-memory .NET-from-shellcode loading — especially recovered from an internet-facing IIS/Exchange host.
- **Likely benign / false lineage:** unmodified public Tunna used by an authorized red team (has a documented engagement + no actor-specific markers/encryption); generic Base64/XOR in normal software; a Donut match on a legitimate pen-test payload. Provenance (where the sample came from) + the *actor-specific* markers, not the open-source skeleton alone, make the call.
- **Pivot next:** a confirmed same-cluster sample → extract its durable strings/constants and feed them to HUNT-01 (listener), HUNT-03 (in-memory execution), and HUNT-04 (encrypted C2) as memory-scan/entropy anchors; hand the verified, non-brittle signatures to detection-engineering as durable YARA/analytics. If the sample came from a live server, this is an active intrusion — escalate to incident-response-coordinator and treat the hash as an IOC pivot (not the hunt basis).

## References

- https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1588/002/
