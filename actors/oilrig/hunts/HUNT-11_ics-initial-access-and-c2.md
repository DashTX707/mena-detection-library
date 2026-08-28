# Hunt: OilRig ICS-adjacent access — watering-hole, HTTP C2 & stolen-credential entry

- **Hypothesis:** If OilRig is pursuing ICS/OT-adjacent objectives (a documented pattern in Gulf energy targeting), then IT/OT-boundary telemetry will show credential-focused watering-hole redirects from third-party sites, HTTP C2 from IT hosts that bridge to OT, and stolen valid credentials used to authenticate into ICS-adjacent systems — activity that maps to ATT&CK for ICS but is observed on the IT side of the boundary.
- **ATT&CK:**
  - T0817 — Drive-by Compromise (ICS) (initial-access)
  - T0869 — Standard Application Layer Protocol (ICS) (command-and-control)
  - T0859 — Valid Accounts (ICS) (initial-access)
- **Actor procedure:** OilRig **used watering-hole attacks to collect credentials for ICS network access**, **communicated with C2 using HTTP requests**, and **used stolen credentials to gain access to victim machines** — the same tradecraft its Enterprise techniques describe, mapped into the ICS domain for OT-boundary targeting of energy/critical-infrastructure victims.
- **Why a hunt, not a rule:** the watering-hole compromise happens on third-party sites (off-victim), HTTP C2 blends with normal web traffic, and stolen-credential access looks legitimate. Detection requires correlating IT-side proxy/auth telemetry with the specific OT-boundary hosts and accounts — context-heavy analysis and baselining of the (usually small, well-known) IT↔OT communication set, not a generic alert.

## Data sources required

- Proxy / web-gateway logs from IT hosts that bridge to OT (referrers, redirects, credential-form POSTs, HTTP C2 shape)
- Authentication logs for ICS-adjacent / engineering-workstation accounts (jump hosts, historians, HMIs' Windows layer)
- IT/OT boundary firewall / NetFlow (which IT hosts talk outbound *and* to OT segments)

## Query starting point

Platform: `Splunk SPL`

```
(index=proxy OR index=firewall OR index=auth)
| eval host_role=case(match(lower(host),"(hmi|scada|historian|eng-ws|jump-ot|ot-)"),"ot_adjacent",1=1,"it")
| where host_role="ot_adjacent"
| eval waterhole=if(match(lower(coalesce(http_referrer,referrer)),"^http") AND match(lower(url),"(login|auth|sso|credential)"),1,0)
| eval http_c2=if(index="firewall" AND dest_port IN (80,8080,443) AND isnotnull(beacon_score) AND beacon_score>0.7,1,0)
| eval anom_logon=if(index="auth" AND (new_source_ip=1 OR odd_hour=1),1,0)
| where waterhole=1 OR http_c2=1 OR anom_logon=1
| stats values(url) as urls values(user) as users values(dest) as dests dc(eval(coalesce(waterhole,http_c2,anom_logon))) as signals by host, host_role
| sort - signals
```

## Triage guidance

- **Likely malicious:** an engineering workstation/jump host redirected through a third-party site into a credential form; periodic HTTP C2-shaped traffic from an OT-adjacent IT host to a rare external destination; an OT-adjacent account authenticating from a new IT source or at an unusual hour, especially soon after a credential-theft event on the IT side.
- **Likely benign / expected:** legitimate vendor remote-support sessions, sanctioned historian/cloud telemetry, and scheduled engineer logons. Baseline the small, known IT↔OT communication and authentication set tightly.
- **Pivot next:** correlate with Enterprise C2 (HUNT-01), valid-accounts (HUNT-06) and watering-hole delivery (HUNT-10); any confirmed OT-boundary credential misuse is a live incident — escalate to IR/OT-security immediately, do not backlog.

## References

- https://attack.mitre.org/groups/G0049/
- https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html
