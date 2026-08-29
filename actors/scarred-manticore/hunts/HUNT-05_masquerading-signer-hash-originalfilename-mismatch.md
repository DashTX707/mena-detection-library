# Hunt: Scarred Manticore masquerading — Cyvera Console EXEs not signed by Palo Alto, System.Drawing.Design.dll outside the GAC, and phantom wlanapi/wlbsctrl DLLs in System32

- **Hypothesis:** If Scarred Manticore has staged an implant under a trusted name, then name-based allow-lists will pass it but three *property mismatches* will not: a standalone EXE presenting as `Cyvera Console` (a Palo Alto Cortex XDR component) that is **not** Authenticode-signed by Palo Alto Networks; a `System.Drawing.Design.dll` loaded from a web/working directory rather than the GAC / .NET reference-assembly path (the SDD backdoor masquerade); and `wlanapi.dll` or `wlbsctrl.dll` present in `C:\Windows\System32` on a Windows Server where they are phantom/absent by default and unsigned — each betrayed by a signer / original-filename / path that contradicts the on-disk name.
- **ATT&CK:**
  - T1036.005 — Masquerading: Match Legitimate Name or Location (stealth) — LIONTAIL EXEs disguised as `Cyvera Console`; SDD backdoor masquerades as `System.Drawing.Design.dll`; phantom hijack DLLs use trusted system-DLL names (`wlanapi.dll`, `wlbsctrl.dll`) placed in System32
- **Actor procedure:** The actor disguises implants as legitimate software/system components to defeat name-based trust: standalone LIONTAIL executables are disguised as `Cyvera Console` (a component of Palo Alto Cortex XDR); the SDD standalone .NET passive backdoor masquerades as the legitimate .NET library `System.Drawing.Design.dll`; and the phantom-hijack DLL variants use trusted system DLL names (`wlanapi.dll`, `wlbsctrl.dll`) placed directly in `C:\Windows\System32`, where those names do not exist by default on Windows Server installs. In every case the *name* is legitimate — only the signer, the PE `OriginalFileName`/`Company` metadata, the file hash, and the on-disk *path* reveal the substitution.
- **Why a hunt, not a rule:** masquerading is engineered specifically to beat name allow-lists and casual eyeballing, so the filename string is worthless as an alert (Level 1) and a hash IOC dies on the next build. The durable discriminators (Summiting Level 2–3 — property mismatch the actor can't remove without losing the disguise) are *contradictions between the claimed identity and the file's verifiable properties*: a `Cyvera Console` binary whose Authenticode signer is not "Palo Alto Networks" (or is unsigned/self-signed); a `System.Drawing.Design.dll` whose load path is not the GAC/NI cache and whose strong-name/publisher doesn't match Microsoft's; a `wlanapi.dll`/`wlbsctrl.dll` that exists in System32 on a server at all, unsigned, not matching the Microsoft catalog hash. Deciding "this name should be signed by X and live at path Y" requires a per-vendor/per-OS baseline of legitimate signers and locations — analyst correlation, not a single threshold. Stack the anomalies: name-match **+** signer/metadata/path mismatch on the same file is the finding.

## Data sources required

- Sysmon EID 1 (process create) and EID 7 (image load) with `OriginalFileName`, `Company`, `Product`, `Signature`, `SignatureStatus`, `Signed`, `Hashes`, and full `Image`/`ImageLoaded` path
- Authenticode/catalog signature verification (EDR file-reputation, or `Get-AuthenticodeSignature`) — signer subject vs claimed vendor
- GAC / .NET assembly inventory (fusion log or assembly path) to know where `System.Drawing.Design.dll` legitimately loads from
- Golden hashes / Microsoft file catalog for `wlanapi.dll`/`wlbsctrl.dll` and a server-DLL baseline (these names phantom-absent by default)

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* (EventCode=1 OR EventCode=7)
| eval img=lower(coalesce(Image, ImageLoaded))
| eval name=mvindex(split(img,"\\"),-1)
| eval signer=lower(coalesce(Signature,"")), sigstat=lower(coalesce(SignatureStatus,"")), signed=lower(coalesce(Signed,""))
| eval company=lower(coalesce(Company,"")), orig=lower(coalesce('OriginalFileName',""))
/* Case 1: Cyvera Console not signed by Palo Alto */
| eval m_cyvera=if((match(orig,"(?i)cyvera") OR match(company,"(?i)cyvera|palo alto") OR match(name,"(?i)cyvera"))
                   AND NOT match(signer,"palo alto"),1,0)
/* Case 2: System.Drawing.Design.dll loaded from outside the GAC / NI cache */
| eval m_sdd=if(name="system.drawing.design.dll"
                AND NOT match(img,"(?i)\\\\(assembly\\\\gac|windows\\\\microsoft\.net|dotnet)\\\\"),1,0)
/* Case 3: phantom system DLL present/loaded on a server, unsigned or wrong hash */
| eval m_phantom=if((name="wlanapi.dll" OR name="wlbsctrl.dll")
                    AND match(img,"(?i)\\\\windows\\\\system32\\\\")
                    AND (signed="false" OR sigstat!="valid"),1,0)
| where m_cyvera=1 OR m_sdd=1 OR m_phantom=1
| table _time host img name orig company signer sigstat signed Hashes ParentImage
```

For any hit, verify the Authenticode signer subject against the claimed vendor and compare `Hashes` to the Microsoft catalog / known-good; a `System.Drawing.Design.dll` in a web-content or working dir loaded into `w3wp.exe` is especially high-signal.

## Triage guidance

- **Likely malicious:** a `Cyvera Console` EXE not signed by Palo Alto Networks (unsigned/self-signed/other signer); a `System.Drawing.Design.dll` loaded from a web/working/System32 path instead of the GAC, unsigned or with a non-Microsoft strong name, especially inside `w3wp.exe`; any `wlanapi.dll`/`wlbsctrl.dll` present in System32 on a server, unsigned or not matching the catalog hash; PE `OriginalFileName`/`Company` contradicting the on-disk name.
- **Likely benign / expected:** the genuine Cortex XDR `Cyvera Console` signed by Palo Alto in its real install path; `System.Drawing.Design.dll` loading from the GAC/NI cache for a legit .NET app; workstations/older Windows where `wlanapi.dll` legitimately exists (this hunt is scoped to *servers* where it is phantom). Correct signer + correct canonical path clears the file.
- **Pivot next:** a confirmed masqueraded file is the loader — pivot to its passive listener (HUNT-01), its in-memory execution (HUNT-03), and its encrypted C2 (HUNT-04); pivot the phantom-DLL name to the service-enablement persistence (`sc.exe config Eaphost start=auto` / IKEEXT — detection lane) that triggers its load. Hash the file for HUNT-07 code-similarity/attribution. A confirmed masqueraded implant on a live server is an active intrusion — escalate to incident-response-coordinator; the confirmed hash goes to detection-engineering as a block (IOC pivot, not the hunt basis). The *signer-vs-claimed-vendor mismatch* logic itself is repeatable and precise — hand it to detection-engineering as a durable analytic.

## References

- https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/
- https://attack.mitre.org/techniques/T1036/005/
