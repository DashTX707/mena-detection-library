# Hunt: UNC1860 masquerading — STAYSHANTE disguised as legitimate Windows server files and TEMPLEDROP posing as a signed AV driver, surfaced via signer/hash/original-filename mismatch

- **Hypothesis:** If UNC1860 artifacts are hiding in plain sight on a compromised server, then — because they masquerade by *name and location* rather than by beacon — the evidence is a metadata mismatch: a file whose on-disk name/path claims to be a legitimate Windows server component or a known AV driver, but whose signer, hash, or PE `OriginalFilename`/version metadata does **not** match the genuine article. STAYSHANTE is disguised as legitimate Windows server files placed in expected web-content/system locations; TEMPLEDROP repurposes a legitimately-signed Iranian *Sheed AV* driver, so it passes a signature check while sitting where a real system driver would. The finding is a name/location that matches an expected component while the signer/hash/original-filename does not — a path/property mismatch, ideally stacked on another lane (HUNT-01 listener, HUNT-03 driver).
- **ATT&CK:**
  - T1036.005 — Masquerading: Match Legitimate Name or Location (stealth) — STAYSHANTE is disguised as legitimate Windows server files, and TEMPLEDROP masquerades as / repurposes a legitimately-signed antivirus driver, blending UNC1860 artifacts into expected system components by name and location

- **Actor procedure:** UNC1860 deliberately names and places its artifacts to look like expected system components. STAYSHANTE (the passive webshell deployed via VIROGREEN) is disguised as legitimate Windows server files so it blends into IIS web-content directories and system paths, defeating name-based allow-lists and casual review. TEMPLEDROP takes a real, correctly-signed third-party AV filesystem filter driver and repurposes it — the file name, location, and even the digital signature look legitimate, so signature-status and name-based checks pass. The masquerade is a force-multiplier across the toolset: it makes the passive listener (HUNT-01) and the kernel driver (HUNT-03) harder to spot during triage.
- **Why a hunt, not a rule:** name/location masquerading is engineered specifically to defeat name-based allow-lists, and TEMPLEDROP's *valid* signature defeats signature-status rules — so the two cheapest automated checks both pass. You cannot write a static name rule (the actor picks legitimate names) or a signer rule (the AV driver is genuinely signed). The durable observable (Summiting Level 3–4: this keys on property mismatch, which the actor cannot resolve without giving up the disguise) is *relational and comparative*: a file claiming a well-known identity whose real properties (hash not matching the known-good for that name, `OriginalFilename`/`CompanyName` metadata inconsistent with the claimed component, an AV driver present where that AV product is not installed, a file in a location that component never legitimately occupies). Building the known-good name→hash/signer map and adjudicating each mismatch is analyst work — a threshold cannot do it.

## Data sources required

- Sysmon EID 1 (process create) and EID 7 (image load) with `OriginalFileName`, `Signature`, `SignatureStatus`, `Company`, `Hashes` — compare the claimed identity against the known-good map
- Sysmon EID 11 (file create) in IIS web-content / system directories, and file-integrity monitoring on those paths — new/modified files masquerading as server components
- A known-good baseline: authoritative name→hash/signer/OriginalFilename map for legitimate Windows server binaries and installed drivers (e.g. from a golden image / Microsoft catalog), plus per-host AV-product inventory
- Sysmon EID 6 (driver load) signer/hash for the AV-driver-vs-installed-product cross-check (shared with HUNT-03)

## Query starting point

Platform: `Splunk SPL` (claimed-identity vs actual-property mismatch)

```
# (a) File whose name matches a known system/AV component but whose hash/signer does not match known-good
index=endpoint source=*Sysmon* (EventCode=1 OR EventCode=7 OR EventCode=6)
| eval fname=lower(replace(coalesce(Image,ImageLoaded),".*\\\\","")), orig=lower(OriginalFileName)
| lookup known_good_binaries name AS fname OUTPUT good_sha256, good_signer, good_originalname
| where isnotnull(good_sha256)
      AND (SHA256!=good_sha256 OR Signature!=good_signer
           OR (isnotnull(orig) AND orig!=good_originalname))
| table _time host fname Image ImageLoaded Signature SignatureStatus OriginalFileName SHA256 good_signer good_sha256

# (b) Original-filename / claimed-name mismatch (binary renamed to look like a system file)
index=endpoint source=*Sysmon* EventCode=1
| eval fname=lower(replace(Image,".*\\\\","")), orig=lower(OriginalFileName)
| where isnotnull(orig) AND fname!=orig
      AND match(fname,"(?i)^(svchost|lsass|w3wp|inetinfo|services|winlogon|iisstart)\.")
| table _time host Image OriginalFileName Company Signature ParentImage

# (c) STAYSHANTE-style: new file masquerading as a server component in web-content dirs
index=endpoint source=*Sysmon* EventCode=11
| where match(TargetFilename,"(?i)\\\\inetpub\\\\.*\\.(aspx|asmx|ashx|dll)$")
| lookup known_good_binaries name AS TargetFilename OUTPUT good_sha256
| where isnull(good_sha256)      /* not a known-good server file, but named like one */
```

Adjudicate each mismatch against the known-good map and the host's installed-product inventory; a matching claimed identity with a non-matching hash/signer/OriginalFilename or an implausible location is the core signal.

## Triage guidance

- **Likely malicious:** a binary named like a core system process but with a non-matching `OriginalFilename`/hash or running from a non-standard path; a *Sheed AV* (or any AV) driver whose product is not installed on the host (shared with HUNT-03); a file in `inetpub` named/typed like a legitimate server component but not in the known-good set; any of these on a passive-listener host (HUNT-01) or overlapping a prior APT34/OilRig compromise.
- **Likely benign / expected:** legitimate renamed launchers and vendor tools with a documented `OriginalFilename` that differs from the on-disk name (baseline and allow-list them); genuine system binaries with valid known-good hashes; real AV drivers on hosts that *do* run that product; custom in-house web components in `inetpub` with a known provenance. The claim-vs-property *mismatch*, not the name alone, makes the call.
- **Pivot next:** for a confirmed masquerade, pivot to what it enables — the passive listener (HUNT-01), the kernel driver / file protection (HUNT-03), the in-memory loader (HUNT-04) — and YARA/cluster the sample against the toolset (HUNT-06); cross-reference the detection lane for STAYSHANTE/BASEWALK webshells (T1505.003) and the driver loads (T1014/T1588.002). A confirmed masqueraded implant on a live server is an active intrusion — escalate to incident-response-coordinator. Once the known-good name→hash/signer map exists, the claimed-name-vs-actual-property mismatch is repeatable and precise — hand to detection-engineering (Summiting Level 3–4).

## References

- https://securityaffairs.com/168656/apt/unc1860-provides-iran-linked-apts-access-middle-east.html
- https://thehackernews.com/2024/09/iranian-apt-unc1860-linked-to-mois.html
- https://attack.mitre.org/techniques/T1036/005/
