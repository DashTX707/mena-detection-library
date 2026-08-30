# Hunt: Predatory Sparrow — prior-reconnaissance evidence & internal signage/HMI defacement staging

- **Hypothesis:** Predatory Sparrow arrives already knowing the target — hardcoded internal paths, domain-controller layout, and backup infrastructure appear in its toolchain, meaning **detailed reconnaissance (T1592) preceded deployment**. If the actor is currently in a pre-attack recon phase in *our* estate, the tell is enumeration and read-access aimed at the two things it always needs before detonation: (1) the **internal topology it will later hardcode** — SYSVOL script paths, DC/GPO config, backup (Veeam) servers, share layouts — and (2) the **internal display/signage and HMI control surfaces** it defaces for psychological effect. The actor defaced railway station arrival/departure boards ("call 64411") and roadside/fuel billboards ("Khamenei, where is our fuel?"). Signage and HMI controllers are OT-adjacent, rarely logged, and rarely touched by normal IT — so *any* discovery/read access to a signage CMS, digital-signage player, or HMI web console from an enterprise identity is a high-value anomaly. The finding is an entity that stacks **recon of backup/DC/SYSVOL infrastructure AND unexpected access to a signage/HMI control surface** — the two halves of "learn the estate, then find the screens to hijack."
- **ATT&CK:**
  - T1592 — Gather Victim Host Information (reconnaissance) — the toolchain's hardcoded `\\railways.ir\sysvol\...\env.cab`, DC-config awareness, and Veeam-backup knowledge prove substantial prior host/infrastructure recon; hunt for that recon happening now.
  - (Detection-lane cross-reference — internal defacement itself is routed to the detect lane as T1491.001; this hunt targets the *staging/recon* that precedes it, where signage/HMI systems are usually un-instrumented and only a hunt can reach.)

- **Actor procedure:** SentinelLabs recovered a toolchain whose artifacts reveal the actor already possessed detailed environment knowledge before deployment: a hardcoded internal staging path on the railways SYSVOL share (`\\railways.ir\sysvol\railways.ir\scripts\env.cab`), awareness of the domain-controller configuration (it distributes via GPO and later unjoins hosts from the DC), and knowledge of the Veeam backup infrastructure (recovery is deliberately sabotaged). Separately, the actor consistently **hijacks internal display systems for messaging** — station boards and fuel billboards — which requires it to first locate and reach the signage/HMI control layer. Recon (T1592) and signage-defacement are two ends of the same preparation: map the estate, identify the recovery and distribution chokepoints, and find the screens the public will see.

- **Why a hunt, not a rule:** Enumerating SYSVOL, listing DCs, and browsing a backup server are things administrators, backup software, and asset-inventory tools do all day — an alert on any one is pure noise. Signage/HMI systems typically emit little or no security telemetry, so there is frequently *nothing to alert on* for the defacement itself (that gap is itself a finding — see below). The value is in **correlating** low-grade recon signals with rare access to an OT-adjacent display surface and judging whether an entity is *assembling target knowledge*. That correlation and the visibility-gap assessment are hunt work. If the estate turns out to have a signage CMS that *does* log content changes, a scoped "unauthorized content push to signage outside change-control" analytic is a clean handoff to detection-engineering.

## Data sources required

- Directory/share enumeration telemetry: SYSVOL/NETLOGON access (5145 object-access on the SYSVOL share), LDAP/AD recon (4662, directory queries for DC/GPO/OU structure), `net`/`nltest`/`dsquery`/AD-PowerShell command-line via EDR
- Backup-infrastructure access: authentication and file/console access to Veeam / backup servers by identities that are not the backup service account (the actor specifically maps backup before sabotaging recovery)
- Signage/HMI control-surface access: web-console/RDP/HTTP auth logs for digital-signage CMS or players and HMI/engineering-workstation consoles; **if these systems produce no logs, document that as a visibility-gap finding**
- Asset inventory / expected-reader baseline (from the hunting wiki) distinguishing sanctioned inventory scanners and backup jobs from unexpected human-driven recon

## Query starting point

Platform: `Splunk SPL` — stack "infrastructure recon" and "signage/HMI access" on the same actor entity

```spl
(* SYSVOL/AD/backup recon by an entity *)
(index=wineventlog (EventCode=5145 Share_Name="*\\SYSVOL" OR Share_Name="*\\NETLOGON")
 OR (EventCode=4662 Properties="*domainDNS*" OR Properties="*groupPolicyContainer*")
 OR (index=edr process_name IN ("nltest.exe","dsquery.exe","net.exe","net1.exe","powershell.exe")
     AND (command IN ("*Get-ADDomainController*","*get-adcomputer*","*/domain_trusts*","*sysvol*","*veeam*","*backup*"))))
| eval signal="recon"
| append
  [* Access to signage CMS / HMI control surfaces by non-service identities *
   search index=web OR index=proxy OR index=wineventlog
     (dest_host IN (SIGNAGE_CMS_HOSTS) OR dest_host IN (HMI_ENGINEERING_HOSTS) OR uri_path IN ("*/signage*","*/playlist*","*/hmi*"))
     NOT user IN (SIGNAGE_SVC_ACCOUNTS, HMI_SVC_ACCOUNTS)
   | eval signal="signage_hmi_access"]
| stats dc(signal) as signal_types values(signal) as signals values(dest_host) as targets
        min(_time) as first values(command) as cmds by user, src_host
| where signal_types>=2                       /* stacked: recon AND signage/HMI touch = target-knowledge assembly */
| convert ctime(first)
| sort - signal_types
```

## Triage guidance

- **Likely malicious:** a single human-driven identity that both enumerates SYSVOL/DC/GPO structure *and* browses/authenticates to a digital-signage console or HMI engineering workstation it has no job function to touch; recon queries specifically targeting **backup infrastructure** (Veeam servers, backup catalogs) from a non-backup account — the actor maps backups precisely to defeat recovery; PowerShell/`net` recon of DC and share topology immediately preceding first access to an OT-adjacent display surface.
- **Likely benign / expected:** asset-discovery tools (Lansweeper, Nessus, SCCM), backup jobs, and GPO-management consoles routinely read SYSVOL and enumerate AD; signage vendors and facilities staff legitimately reach signage CMS during business hours — baseline these service accounts and scanner hosts in the wiki and suppress them. A single AD query by a helpdesk tool is expected; the *stack* of infra-recon + unexpected signage/HMI access on one non-privileged identity is not.
- **Pivot next:** if an entity stacks both signals, treat it as active target-knowledge assembly and pivot to HUNT-01 (how did it get in — trusted relationship / valid account) and HUNT-03 (pre-detonation host discovery). Escalate to incident-response-coordinator if the same entity then stages archives or scheduled tasks. **If signage/HMI systems emit no telemetry at all, raise that as a standalone visibility-gap finding** — "we cannot see defacement staging on our public-facing screens" is actionable and should feed OT-monitoring onboarding, not be silently skipped.

## References

- https://www.sentinelone.com/labs/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll/
- https://www.picussecurity.com/resource/blog/predatory-sparrow-inside-the-cyber-warfare-targeting-irans-critical-infrastructure
- https://attack.mitre.org/techniques/T1592/
- https://attack.mitre.org/techniques/T1491/001/
