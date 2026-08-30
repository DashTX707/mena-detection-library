# Hunt: Volatile Cedar — pre-intrusion scanning & vuln-probing of the internet-facing web estate

- **Hypothesis:** If Volatile Cedar is preparing (or has already staged) an intrusion against us, then before any web shell or Explosive implant lands there will be a *reconnaissance signature at our perimeter*: distributed, low-and-slow probing of our published IP blocks that converges on the exact software families the group exploits — Atlassian Confluence, Atlassian Jira and Oracle 10g — with requests fingerprinting versions and testing the specific 1-day CVE paths (CVE-2019-3396 `/rest/tinymce/1/macro/preview`, CVE-2019-11581 Jira contact-admin SSTI, CVE-2012-3152 Oracle Reports) or SQL-injectable parameters. The tell is not one scan (the internet scans everyone constantly) but a *source cluster whose probing is narrowly selective for our vulnerable Atlassian/Oracle surface and then goes quiet on the hosts that answered as exploitable* — reconnaissance that discriminates is targeting, not background noise. The off-victim corroborator is external attack-surface / passive-DNS intel showing the same source infrastructure enumerating our ASN.
- **ATT&CK:**
  - T1595.001 — Active Scanning: Scanning IP Blocks (reconnaissance) — sweeping our published IP ranges to discover exposed web/app servers before target selection
  - T1595.002 — Active Scanning: Vulnerability Scanning (reconnaissance) — version/CVE-path probing that narrows onto vulnerable Confluence/Jira/Oracle 10g instances

- **Actor procedure:** Both Check Point (2015) and ClearSky (2021) describe an opportunistic, internet-wide server-selection model as the *front* of every Volatile Cedar intrusion. The group sweeps IP space for exposed web/application servers, fingerprints the software, and selects unpatched Atlassian Confluence (CVE-2019-3396), Jira (CVE-2019-11581) and Oracle 10g (CVE-2012-3152) instances — plus SQL-injectable parameters in the original campaign — before dropping the Caterpillar/JSP web shell. ClearSky attributed ~250 breached servers, primarily at telecoms and ISP/hosting providers, to exactly this scan→select→exploit funnel.
- **Why a hunt, not a rule:** The scanning happens off-victim at the perimeter and rarely attributes cleanly to any one actor — the raw event is indistinguishable from the constant background of internet-wide scanners (Shodan, Censys, criminal mass-scanners). A standalone "someone probed our Confluence" alert would fire thousands of times a day. The finding only exists in the *correlation*: a source cluster that is selective for our specific vulnerable stack, that revisits only the hosts that answered as exploitable, and that matches external infrastructure intel — that fusion and judgement is hunt work, not an alertable primitive.

## Data sources required

- WAF / reverse-proxy / edge access logs (URI, User-Agent, source IP, response code) for internet-facing Atlassian/Oracle/IIS hosts
- External attack-surface management (ASM) inventory: which of our published hosts run Confluence/Jira/Oracle and at what version/patch state
- Passive-DNS / threat-intel on scanning-source infrastructure keyed to our ASN and domains
- NetFlow / firewall connection logs for the perimeter IP blocks (fan-in / fan-out per source)

## Query starting point

Platform: `Splunk SPL` — surface source IPs whose probing is narrowly selective for the CVE paths this actor exploits, then look for the revisit-only-the-vulnerable pattern.

```spl
index=web sourcetype=waf OR sourcetype=proxy earliest=-14d
| eval cve_probe=case(
      like(uri_path,"%/rest/tinymce/1/macro/preview%"), "CVE-2019-3396_confluence",
      match(uri_path,"(?i)secure/ContactAdministrators|/servicedesk/customer"), "CVE-2019-11581_jira",
      match(uri_path,"(?i)/reports/rwservlet"), "CVE-2012-3152_oracle10g",
      match(uri_query,"(?i)(union(\s|\+)+select|' or 1=1|sqlmap)"), "sqli_probe",
      true(), null())
| where isnotnull(cve_probe)
| stats dc(cve_probe) as distinct_cve_families
        values(cve_probe) as probes
        dc(dest_ip) as hosts_touched
        count as probe_hits
        earliest(_time) as first_seen latest(_time) as last_seen
        by src_ip
| where distinct_cve_families>=2 OR probe_hits>=20
| eval window_hours=round((last_seen-first_seen)/3600,1)
| sort - distinct_cve_families - probe_hits
```

## Triage guidance

- **Likely malicious:** a source (or a tight cluster sharing ASN/JA3/User-Agent) that probes two or more of the exact CVE families above, then *stops broad scanning and returns only to the hosts that responded as vulnerable*; probing that specifically fingerprints Confluence/Jira/Oracle versions rather than spraying generic paths; a scan source that later appears in the web-shell or C2 hunts against the same host (cross-ref HUNT-02, detection pack T1190/T1505.003); external ASM/passive-DNS intel naming the same source enumerating our ASN.
- **Likely benign / expected:** licensed vulnerability scanners (Qualys, Tenable, Rapid7) and internal ASM tooling — baseline and allow-list their source ranges; commercial internet-wide researchers (Shodan/Censys/BinaryEdge) that touch *everything* uniformly rather than selecting your vulnerable stack; a single opportunistic CVE spray with no follow-up. Selectivity plus a follow-up return visit is what separates targeting from noise.
- **Pivot next:** for any host that both answered as vulnerable and was revisited, immediately pivot to the web-shell/exploitation detection lane (T1190, T1505.003) and check web roots for Caterpillar/JSP file writes since first probe; preserve the source infrastructure as attribution intel and push it to the C2/infrastructure hunt (HUNT-02). If a web shell or post-exploit child process is found, this is an active intrusion — escalate to incident-response-coordinator.

## References

- https://www.clearskysec.com/wp-content/uploads/2021/01/Lebanese-Cedar-APT.pdf
- https://blog.checkpoint.com/security/volatilecedar/
- https://attack.mitre.org/techniques/T1595/001/
- https://attack.mitre.org/techniques/T1595/002/
