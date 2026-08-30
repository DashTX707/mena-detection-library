# Hunt: Pioneer Kitten open-source tooling staging and security-policy exemption abuse

- **Hypothesis:** If Pioneer Kitten has a foothold and is preparing to operationalize their toolkit, then two low-signal precursors appear together before the tools ever "act": (a) the actor's favored **public tools** — Ligolo/ligolo-ng, ngrok, Meshcentral, AnyDesk, Mimikatz, Plink/PsExec — land on hosts as **never-before-seen binaries** for our estate (staged, not yet run), and (b) around the same time the actor **requests security-policy / zero-trust exemptions or allowlisting** for "IT tools" so those binaries won't be blocked by EDR/application control. The internal tell is a change/exemption ticket or an allowlist modification that grants an exception for an unsanctioned RMM/tunneling tool, time-correlated with that tool appearing on disk. The hunt fuses software-inventory novelty with change-ticket / allowlist-config review.
- **ATT&CK:**
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — actors obtain and operationalize Ligolo/ligolo-ng, ngrok, Meshcentral, AnyDesk, Mimikatz, Plink/PsExec
  - T1098 — Account Manipulation (persistence) — actors request exemptions to the victim's zero-trust application and security policies so their tools are allowlisted

- **Actor procedure:** Pioneer Kitten equips itself with commodity, dual-use open-source tooling — Ligolo and ngrok for tunneling, Meshcentral and AnyDesk for remote access, Mimikatz for credential theft, Plink/PsExec historically for pivoting. Because these trip application-control and EDR, the actors **enter security-exemption tickets to the network security device or its managing contractor to get their tools allowlisted**, and request exemptions to zero-trust application policies — turning a control process into a persistence/defense-evasion enabler so their toolkit runs unimpeded.
- **Why a hunt, not a rule:** Tool acquisition (T1588.002) happens off-endpoint; the exemption request (T1098) is largely a *social/process* action — a ticket, an email, an allowlist edit — that lives in ITSM/change systems outside standard security telemetry, so there is nothing to alert on in EDR. And the tools are genuinely dual-use: MSPs run Meshcentral/AnyDesk, network engineers run Plink, pentesters stage ngrok — a naive "AnyDesk seen" rule is noise. The finding is the *stack*: an unsanctioned tool appearing as a never-before-seen binary **plus** a matching allowlisting exemption granted for it **plus** the requester/host being out of character. That correlation across the ITSM and endpoint domains is judgement-heavy hunt work. A durable sub-signal (e.g. an application-control allowlist entry added for an RMM/tunneling binary hash) can be handed to detection-engineering as a config-drift alert.

## Data sources required

- Software / binary inventory + EDR file-write telemetry (first-seen date per binary across the fleet) — Ligolo, ngrok, Meshcentral, AnyDesk, Mimikatz, Plink, PsExec
- Application-control / EDR allowlist configuration change log (exemptions added, by whom, for which hash/path/publisher)
- ITSM / change-management ticketing — security-exemption and zero-trust policy-exception requests (text search for tool names / "allowlist" / "exception")
- Sysmon EID 1 (process create) for staged-but-run correlation; proxy/DNS for `*.ngrok.io`, Meshcentral/AnyDesk endpoints (cross-ref detection pack T1219/T1572)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — never-before-seen actor tool intersected with a fresh allowlisting exemption

```kusto
// (a) Actor toolkit landing as a never-before-seen binary in the estate
let firstSeen = DeviceFileEvents
    | where TimeGenerated > ago(30d)
    | where FileName has_any ("ligolo","ngrok","meshcentral","meshagent","anydesk","mimikatz","plink","psexec")
          or InitiatingProcessVersionInfoOriginalFileName has_any ("ligolo","ngrok","AnyDesk","MeshAgent")
    | summarize firstWrite = min(TimeGenerated), hosts = dcount(DeviceName),
                hostset = make_set(DeviceName, 20) by FileName, SHA256
    | join kind=leftanti (                              // exclude binaries present >30d ago (baselined tools)
        DeviceFileEvents | where TimeGenerated between (ago(365d)..ago(30d))
        | where FileName has_any ("ligolo","ngrok","meshcentral","anydesk","mimikatz","plink","psexec")
        | summarize by SHA256) on SHA256;
// (b) Allowlisting / policy exemptions granted for those same tools (config-change or ITSM export table)
let exemptions = ApplicationControlChanges                 // or ITSM_Tickets export
    | where TimeGenerated > ago(30d)
    | where ChangeType == "AllowlistAdd" or RequestText has_any ("exemption","allowlist","exception","zero-trust")
    | where RuleTarget has_any ("ngrok","meshcentral","anydesk","ligolo","plink","psexec") or RequestText has_any ("ngrok","meshcentral","anydesk","ligolo")
    | project exemptTime = TimeGenerated, Requester, Approver, RuleTarget, RequestText;
firstSeen
| extend key = tostring(FileName)
| join kind=leftouter (exemptions | extend key = tostring(RuleTarget)) on key
| order by firstWrite desc
```

## Triage guidance

- **Likely malicious:** an actor tool (ngrok, Ligolo, Meshcentral, AnyDesk, Mimikatz, Plink) appearing as a never-before-seen binary on a server or non-IT host, especially staged in a user-writable/Downloads path; a security-exemption or allowlisting ticket requesting an exception for an RMM/tunneling tool that is not part of the sanctioned toolset, filed by or on behalf of an unusual account and time-correlated with that binary landing; an exemption granted then immediately followed by the tool executing and beaconing to `*.ngrok.io`/Meshcentral.
- **Likely benign / expected:** sanctioned MSP/helpdesk uses AnyDesk or Meshcentral fleet-wide under a documented policy — baseline the approved hashes, publishers and management servers; network engineers legitimately carry Plink/PsExec; a genuine change ticket from a known admin referencing the sanctioned RMM is routine. A known-good hash of a sanctioned tool with a standing policy is expected; a new hash, a new host class, or an ad-hoc exemption for an unlisted tunneling tool is not.
- **Pivot next:** confirmed staging of unsanctioned tunneling/RMM plus a matching exemption request is active operational prep — pivot to whether the tool has run and beaconed (detection pack T1219/T1572/T1090), pull the credential-access chain if Mimikatz/Plink is present (T1003.001), review who approved the exemption and revoke it, and if execution + egress is confirmed escalate to incident-response-coordinator. Hand the allowlist-config-drift observable (RMM/tunneling hash added to application-control) to detection-engineering as a standing alert.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a
- https://attack.mitre.org/groups/G0117/
- https://attack.mitre.org/techniques/T1588/002/
- https://attack.mitre.org/techniques/T1098/
