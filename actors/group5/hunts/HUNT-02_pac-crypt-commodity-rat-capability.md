# Hunt: PAC Crypt-packed commodity RATs (njRAT / NanoCore) capability tracking

- **Hypothesis:** If Group5 obtained and deployed commodity RATs packed with the Iranian "PAC Crypt" crypter, then .NET samples on disk or in mail/proxy quarantine will carry the crypter's tell-tale artifacts — a small AES/Base64-decoding .NET stub whose payload lives in the resource section, plus debug PDB strings exposing the `mr.tekide` developer alias (e.g. `paccryptnano core dehgani-vds`, `paccrypt11njratmalii`) — even when the wrapped njRAT/NanoCore payload itself is not statically detected. This is a high-entropy / masquerading (benign-looking .NET assembly) anomaly stacked with a never-before-seen PDB-string artifact.
- **ATT&CK:**
  - T1588.002 — Obtain Capabilities: Tool (resource-development)
  - T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File (stealth)
- **Actor procedure:** Group5 used no custom implants — it relied entirely on off-the-shelf njRAT and NanoCore Windows RATs (and DroidJack on Android), packing each with the "PAC Crypt" .NET crypter to defeat static AV. The crypter Base64-encoded the PE, embedded it AES-encrypted in the resource section behind a .NET stub, and — compiled in debug mode — leaked PDB strings tying the tooling to the `mr.tekide` alias (crypter.ir / crypting.org, Ashiyane Digital Security Team). Only ~12.5% of samples were AV-detected at analysis time.
- **Why a hunt, not a rule:** The packing exists specifically to break static hash/AV signatures, and the payload changes per-build, so hunting the wrapped hash is futile. The robust, Summiting-Level-4 (technique-implementation-core) observable is the crypter *stub construction and its PDB artifacts* — properties the operator would have to abandon the tooling to change. This is a retro-hunt/YARA sweep across sample stores and quarantine, requiring analyst confirmation of each hit, not a production detonation rule.

## Data sources required

- Endpoint file inventory / EDR sample collection (PE + .NET metadata, resource sections, PDB paths)
- Mail-gateway and web-proxy quarantine / attachment stores
- Retro-hunt platform capable of YARA over collected binaries (VirusTotal Retrohunt, internal sample lake)
- PE/.NET static-analysis enrichment (CLR header, resource entropy, PDB debug directory)

## Query starting point

Platform: `YARA` (retro-hunt over collected/quarantined samples)

```yara
rule Group5_PAC_Crypt_stub_and_pdb
{
    meta:
        author = "MENA Detection Library — threat-hunter"
        description = "Hunt: PAC Crypt (mr.tekide) crypter stub / PDB artifacts wrapping njRAT/NanoCore"
        actor = "Group5 (G0043)"
        reference = "https://citizenlab.ca/2016/08/group5-syria/"
        note = "HUNT ONLY — confirm hits manually; do not deploy as production detection"
    strings:
        $pdb1 = "paccrypt" ascii nocase
        $pdb2 = "mr.tekide" ascii nocase
        $pdb3 = "dehgani-vds" ascii nocase
        $pdb4 = "paccrypt11njratmalii" ascii nocase
        $net1 = "mscoree.dll" ascii
        $net2 = "FromBase64String" ascii
        $net3 = "System.Security.Cryptography" ascii
    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($pdb1,$pdb2,$pdb3,$pdb4) or
            ($net1 and $net2 and $net3 and filesize < 3MB)
        )
}
```

Companion pivot — Platform: `Splunk SPL` (surface the .NET PDB string in existing EDR image metadata):

```
index=edr sourcetype=*image_load* OR sourcetype=*file*
| search (pdb_path="*paccrypt*" OR pdb_path="*mr.tekide*" OR pdb_path="*dehgani-vds*"
          OR OriginalFileName IN ("putty.exe","dwm.exe"))
| stats count values(pdb_path) as pdb values(file_path) as paths values(sha256) as hashes by host, process_name
```

## Triage guidance

- **Likely malicious:** Any sample carrying a `paccrypt*` / `mr.tekide` / `dehgani-vds` PDB string; a small (<3MB) .NET assembly that Base64/AES-decodes a payload out of its resource section into memory; such a binary delivered as `putty.exe`/`dwm.exe` or a decoy-named dropper. Confirm the unwrapped payload is njRAT or NanoCore.
- **Likely benign / expected:** Legitimate .NET applications that use `FromBase64String`/cryptography for normal features and are signed by a known publisher with a sane PDB path; commercial packers/obfuscators (ConfuserEx, etc.) used by in-house or licensed software — verify signer and provenance. The generic `$net*` branch is broad; treat it as a triage funnel, not a verdict.
- **Pivot next:** On confirmed PAC Crypt / RAT capability, unwrap and identify the RAT family, then pivot to HUNT-03 (RAT surveillance behaviors) and HUNT-04 (RAT file-deletion) on the same host, and hand the masquerading `putty.exe`/`dwm.exe` observable to the detection lane. Live RAT on host → **escalate to incident-response**.

## References

- https://citizenlab.ca/2016/08/group5-syria/
- https://attack.mitre.org/groups/G0043/
- https://attack.mitre.org/techniques/T1588/002/
- https://attack.mitre.org/techniques/T1027/013/
