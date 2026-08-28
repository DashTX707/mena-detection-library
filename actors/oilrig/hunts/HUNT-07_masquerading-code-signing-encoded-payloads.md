# Hunt: OilRig masquerading, stolen code-signing & encoded/encrypted payloads on disk

- **Hypothesis:** If OilRig has delivered tooling to a host, then files on disk will show *property/name/content mismatches* — a `.doc`-named executable, a legit-looking binary (`Adobe.exe`) in a non-standard path, a binary signed with a stolen/unexpected certificate, or a high-entropy encoded/encrypted blob — that deviate from the environment's baseline of where such names, signers and entropy normally appear.
- **ATT&CK:**
  - T1036 — Masquerading (defense-evasion)
  - T1553.002 — Subvert Trust Controls: Code Signing (defense-evasion)
  - T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File (defense-evasion)
- **Actor procedure:** OilRig **uses `.doc` file extensions to mask malicious executables**, **names a copy of the Plink tunnel as `\ProgramData\Adobe.exe`** (legit-name, wrong location), **signs its malware with stolen certificates**, and **encrypts/encodes data in malware including via Base64**.
- **Why a hunt, not a rule:** extension-vs-magic-byte mismatch, signer-reputation anomalies and file-entropy all require dedicated file inspection and per-environment baselining of which signers/paths/entropy are normal; a stolen-but-valid certificate passes signature checks. This is analyst-driven anomaly stacking, not a deterministic alert. (A confirmed stolen thumbprint is handed to detection-engineering as an IOC block.)

## Data sources required

- Sysmon EID 1 (Image, Hashes, Signed, Signature, SignatureStatus) + EID 7 (image/DLL load with signer)
- EDR file metadata (magic-byte vs extension, Authenticode signer + thumbprint, entropy)
- File-integrity / scanning telemetry over `\ProgramData`, `%TEMP%`, `%APPDATA%`, user Downloads

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=1
| eval img=lower(Image)
| eval namemismatch=if(match(img,"\.(doc|docx|pdf|jpg|txt)$") AND ImageLoaded="", 1, 0)
| eval decoy_path=if(match(img,"\\\\programdata\\\\(adobe|chrome|update|svchost|winlogon)\.exe$")
        OR match(img,"\\\\(temp|appdata)\\\\.*\\\\(svchost|lsass|adobe|update)\.exe$"), 1, 0)
| eval bad_sign=if(Signed="true" AND (SignatureStatus!="Valid" OR match(lower(Signature),"(unknown|test|self)")), 1, 0)
| where decoy_path=1 OR bad_sign=1 OR namemismatch=1
| stats values(img) as images values(Signature) as signers values(Hashes) as hashes
        values(ParentImage) as parents count by host, decoy_path, bad_sign, namemismatch
| sort - count
```

## Triage guidance

- **Likely malicious:** a PE that carries a document/image extension; `Adobe.exe`/`chrome.exe`/`svchost.exe` running from `\ProgramData` or `%TEMP%` instead of its real install path; a binary whose signer is a stolen/unexpected cert or whose signature status is invalid; a high-entropy blob dropped next to a script host.
- **Likely benign / expected:** legitimate software in `\ProgramData` for genuine per-machine installs; self-signed internal tools (enumerate signers); packed-but-legitimate installers. Baseline known-good signers, paths and entropy per app.
- **Pivot next:** hash the file and check reuse across hosts; tie the decoy binary to its launcher (HUNT-09) and any outbound tunnel (HUNT-01, Plink/ngrok); feed a confirmed stolen thumbprint or decoy hash to detection-engineering.

## References

- https://attack.mitre.org/groups/G0049/
