# Hunt: UNC1860 toolset attribution and custom-crypto YARA — clustering the large purpose-built implant library and hunting the OBFUSLAY/CRYPTOSLAY symmetric-encryption constants across samples

- **Hypothesis:** If a suspicious server-side sample recovered from our environment is UNC1860's, then — even with a fresh hash and heavy packing — it will retain **development fingerprints the actor cannot cheaply remove**: the shared OBFUSLAY/CRYPTOSLAY symmetric-encryption constants and custom crypto layer reused to protect payloads and C2 content, plus the structural DNA of the large purpose-built implant family (TEMPLEDOOR, TEMPLEPLAY, TEMPLELOCK, TEMPLEDROP, OATBOAT, TOFULOAD/TOFUDRV, VIROGREEN, STAYSHANTE, BASEWALK, SASHEYAWAY, FACEFACE, SPARKLOAD, TUNNELBOI). This is a *retro-hunt / triage* hypothesis: cluster unknown server-side samples and decoded in-memory payloads against these signatures to (a) attribute an unattributed implant to this cluster and (b) mine durable signatures that survive rebuilds better than any single hash. The custom crypto layer is not a wire signature — it sits inside otherwise-normal HTTPS — so it is hunted in *samples*, not logs.
- **ATT&CK:**
  - T1587.001 — Develop Capabilities: Malware (resource-development) — UNC1860 maintains an unusually large, purpose-built in-house library of passive implants, loaders, controllers and drivers reflecting deep development including kernel-component reverse engineering; the shared tooling family is an attribution/triage signal, not a host detection
  - T1573.001 — Encrypted Channel: Symmetric Cryptography (command-and-control) — CRYPTOSLAY (paired with OBFUSLAY) adds a custom symmetric-crypto layer inside the web channel to defeat content inspection; hunt via YARA on the shared encryption constants in samples, not log detection

- **Actor procedure:** Capability development is off-victim — UNC1860 builds and maintains its implant library on its own infrastructure, so the development itself is never observable in defender host/network logs. It becomes useful to the defender as an *attribution and detection-content signal*: the toolset is tied together by shared code and a reused custom crypto layer. In addition to HTTPS transport, UNC1860 protects payloads and C2 content with symmetric encryption via CRYPTOSLAY, paired with OBFUSLAY obfuscation, adding a crypto layer *inside* the otherwise-normal web channel that defeats content inspection on the wire. Because the constants and routines are reused across the family, they cluster new samples to this actor and yield signatures more durable than a per-build hash.
- **Why a hunt, not a rule:** you cannot alert on an adversary compiling malware on their own machines (Level 0 for host detection), and the custom symmetric-crypto layer rides inside normal TLS — there is no wire signature to match without breaking TLS, and even then the payload is doubly encrypted. The value is realized through *sample triage and code-similarity clustering* — analyst work over a malware corpus and over decoded in-memory dumps (from HUNT-04), not a SIEM query. A single hash YARA rule is brittle (dies on the next build); the durable discriminators (Summiting Level 2–3: shared implementation detail) are the *reused encryption constants and toolmarks* the actor keeps across the family because rewriting them per sample is expensive. Those clustered signatures then graft back onto the live hunts (HUNT-01/03/04) and onto detection-engineering as durable analytics.

## Data sources required

- A malware/sample repository for the environment (EDR quarantine, sandbox submissions, IR-collected server samples) and decoded in-memory dumps from HUNT-04 — this hunt operates over files, not endpoint telemetry
- YARA (with retro-hunt over historical samples) plus a diffing/similarity toolset — BinDiff, ssdeep/TLSH fuzzy hashing, and .NET decompilation (dnSpy/ILSpy) for the managed TEMPLEPLAY/TEMPLELOCK components
- The Mandiant/GCTI "Temple of Oats" technical appendix and the Rewterz IOC advisory for the shared markers/constants and hash set (see cti-pipeline.json `iocs.hashes`)
- (Optional) VirusTotal / Malpedia for external corroboration and imphash/string pivoting

## Query starting point

Platform: `YARA + procedure` (this is triage/attribution, not a log search)

```yara
rule unc1860_shared_toolmarks_and_crypto
{
    meta:
        author = "mena-detection-library"
        description = "Heuristic: shared code-marks and OBFUSLAY/CRYPTOSLAY custom-crypto constants across the UNC1860 implant family (TEMPLEDOOR/TEMPLEPLAY/TEMPLELOCK/TOFULOAD/TOFUDRV/OATBOAT/SASHEYAWAY). Triage/attribution aid — verify hits and replace the placeholder constants with the exact values from the Mandiant appendix before any blocking use."
        reference = "https://thehackernews.com/2024/09/iranian-apt-unc1860-linked-to-mois.html"
        source = "UNC1860 (Iran/MOIS - Temple of Oats)"
    strings:
        // Undocumented HTTP.sys / passive-listener + IOCTL API marks
        $httpsys1 = "HttpReceiveHttpRequest" ascii wide
        $ioctl1   = "DeviceIoControl" ascii wide
        // NOTE: replace the placeholders below with the exact CRYPTOSLAY/OBFUSLAY
        // symmetric-encryption constants and family toolmark strings from the appendix.
        $crypto_const1 = { DE AD BE EF }        // <-- placeholder: real S-box / key schedule constant
        $mark_temple   = "Temple" ascii wide nocase
        $mark_tofu     = "Tofu" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        ( $crypto_const1
          or (any of ($httpsys1,$ioctl1) and any of ($mark_temple,$mark_tofu)) )
}
```

Procedure: retro-hunt this rule (and per-family variants) across the sample corpus and the HUNT-04 memory dumps; for hits, TLSH/ssdeep-cluster them and BinDiff/decompile to confirm the shared CRYPTOSLAY/OBFUSLAY routines and the passive-listener/IOCTL code paths. Cross-reference the 42 hashes in the cti-pipeline IOC set as *pivots* (not the hunt basis — they expire). Promote only *verified* clusters.

## Triage guidance

- **Likely malicious / same-cluster:** a server-side .NET assembly or PE that reuses the OBFUSLAY/CRYPTOSLAY custom symmetric-crypto constants or family toolmark strings, shows the undocumented HTTP.sys/IOCTL passive-listener code path, or clusters (TLSH/ssdeep) with a confirmed family sample — especially recovered from an internet-facing IIS/SharePoint/telecom host in the targeted MENA sectors or one overlapping a prior APT34/OilRig compromise.
- **Likely benign / false lineage:** generic Base64/XOR or standard crypto-library constants in normal software; a `DeviceIoControl`/`HttpReceiveHttpRequest` import in a legitimate self-hosted service or driver (the *import alone* is not the signal — the actor-specific crypto constant / toolmark is); an authorized red-team payload with documented provenance. Provenance plus the *actor-specific* constants, not the generic API marks, make the call.
- **Pivot next:** a confirmed same-cluster sample → extract its durable constants/toolmarks and feed them to HUNT-01 (listener), HUNT-03 (driver/injection), and HUNT-04 (in-memory decode) as memory-scan anchors; hand the verified, non-brittle signatures to detection-engineering as durable YARA/analytics (Summiting Level 2–3). If the sample came from a live server, this is an active access-broker intrusion — escalate to incident-response-coordinator and treat the hash as an IOC pivot, not the hunt basis. Corroborate attribution with the APT34/OilRig victim-overlap signal noted in the intel.

## References

- https://thehackernews.com/2024/09/iranian-apt-unc1860-linked-to-mois.html
- https://securityaffairs.com/168656/apt/unc1860-provides-iran-linked-apts-access-middle-east.html
- https://rewterz.com/threat-advisory/middle-east-network-intrusions-facilitated-by-iranian-apt-unc1860-active-iocs
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1573/001/
