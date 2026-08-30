# Hunt: Arid Viper — actor infrastructure: persona domains, Firebase projects, in-house malware, and ALFA TEaM webshells

- **Hypothesis:** Arid Viper's infrastructure carries a recognizable fingerprint that can be hunted *proactively and off-victim* — before any of our users are hit. If the actor is standing up new capacity, then new persona-style hyphenated domains (first-last name across odd TLDs), new attacker-owned Firebase/Appspot C2 projects, and servers fronted by ALFA TEaM webshells will appear that cluster with known Arid Viper infrastructure by naming convention, registrar/WHOIS pattern, hosting, TLS cert, and malware-family code lineage. The finding is a newly surfaced domain/host/project that matches the persona-domain pattern *and* co-locates or code-links to known Micropsia/SpyC23 tooling — i.e., an unexpected-relationship cluster, not a single lonely lookalike.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — persona-style hyphenated C2 domains (luis-dubuque[.]in, conner-margie[.]com, grace-fraser[.]site) as a registration-pattern pivot.
  - T1583.006 — Acquire Infrastructure: Web Services (resource-development) — attacker-owned Firebase/Appspot projects (skippedtestinapp.firebaseio.com, jolia-16e7b.appspot.com) stood up as resilient FCM C2.
  - T1587.001 — Develop Capabilities: Malware (resource-development) — in-house implant families (Micropsia/PyMicropsia/Arid Gopher/BarbWire/Rusty Viper; SpyC23/VAMP/FrozenCell) tracked via code-lineage/family clustering.
  - T1505.003 — Server Software Component: Web Shell (persistence) — ALFA TEaM webshells administering actor C2, fingerprintable via internet-scan telemetry.

- **Actor procedure:** The group registers persona-style hyphenated domains it solely controls (first-last across `.in/.com/.site/.info/.icu/.club/.live/.tech/.life`) as C2 for both Android and Windows implants, and stands up Google Firebase/Appspot projects (`skippedtestinapp.firebaseio.com`, `lightroom-61eb2.firebaseio.com`, `jolia-16e7b.appspot.com`, `yellwo-473d0.appspot.com`, `rashonal.appspot.com`) for FCM-based C2. It maintains a large in-house dev program iterating implants across Delphi, Python, Go, C++ and Rust (Windows) plus the SpyC23/VAMP/FrozenCell Android lineage, and manages its C2 servers with **ALFA TEaM** webshells (with a Laravel backend behind Arid Gopher C2). The naming convention and shared code are the through-line vendors use to cluster the activity.
- **Why a hunt, not a rule:** This is entirely off-victim resource-development and actor-owned persistence — none of it touches our endpoints, so there is nothing to "alert" on in our estate; the work is proactive infrastructure intel and clustering. Matching is fuzzy and needs analyst judgement: the persona-domain shape (`word-word.oddtld`) has enormous benign overlap, a Firebase project name alone proves nothing, and an ALFA TEaM banner on an internet host isn't attributable without corroboration. The value is stacking anomalies — naming pattern + young privacy-protected WHOIS + shared hosting/cert + code lineage to a known family — into an attributable cluster. Only a confirmed, still-live actor FQDN/project graduates to detection-engineering as a blocklist; the clustering itself stays a hunt.
- **Summiting note:** this hunt deliberately trades up from Level-1 IOCs (a single domain/hash that the actor rotates cheaply) to the durable *registration and code-lineage pattern* — the observable the actor cannot change without abandoning its established tradecraft.

## Data sources required

- Passive DNS / domain-registration feeds (WHOIS, newly-registered-domain streams) for persona-pattern and registrar/nameserver pivoting
- Internet-scan telemetry (Shodan/Censys): ALFA TEaM webshell fingerprints, Laravel-backed C2, TLS cert reuse across candidate hosts
- Firebase/Appspot enumeration + threat-intel on attacker-owned project IDs
- Malware-repository / sandbox feeds (VirusTotal/MalwareBazaar) for Micropsia/SpyC23 family code-lineage clustering and C2 config extraction

## Query starting point

Platform: `Splunk SPL (over passive-DNS + newly-registered-domain feed)` — surface new persona-pattern domains that cluster with known Arid Viper infra

```spl
index=passivedns OR index=newly_registered_domains
``` persona-domain shape: two lowercase name-words, hyphen, on the actor's observed TLD set ```
| rex field=domain "^(?<w1>[a-z]{3,})-(?<w2>[a-z]{3,})\.(?<tld>in|com|site|info|icu|club|live|tech|life)$"
| where isnotnull(w1)
| lookup whois.csv domain OUTPUT registrar, create_date, privacy_protected, ns
| eval age_days = round((now() - strptime(create_date,"%Y-%m-%d"))/86400)
``` stack anomalies: young + privacy-protected + shared nameserver/registrar with known actor domains ```
| eval known_ns = if(ns IN ("<ns-of-known-av-domains>"),1,0)
| eval young = if(age_days < 120,1,0)
| eval priv  = if(privacy_protected="true",1,0)
| eval anomaly_score = known_ns*2 + young + priv
| where anomaly_score >= 3
| table domain age_days registrar ns privacy_protected anomaly_score
| sort - anomaly_score
```

## Triage guidance

- **Likely malicious:** a `word-word.oddtld` domain that is <120 days old, privacy-protected, sharing a nameserver/registrar/hosting-IP or TLS cert with known Arid Viper persona domains, and either fronting an ALFA TEaM webshell or resolving to a host serving APK staging paths; a Firebase/Appspot project whose name matches actor conventions and appears in a sample's extracted C2 config.
- **Likely benign / expected:** `firstname-lastname.com` personal/portfolio sites, small-business hyphenated brands, and legitimate Firebase projects are extremely common — the pattern alone is near-worthless; require at least one corroborating link (shared infra, code lineage, or a sample referencing it) before calling anything.
- **Pivot next:** feed confirmed live actor domains/projects into HUNT-02 (download/DNS matching) and HUNT-04 (Firebase C2) as watchlists, extract and cluster any hosted sample against the Micropsia/SpyC23 families, and route confirmed still-live C2 FQDNs to detection-engineering for proxy/DNS blocklisting and to takedown/registrar-abuse channels.

## References

- https://www.deepinstinct.com/blog/arid-gopher-the-newest-micropsia-malware-variant
- https://blog.talosintelligence.com/arid-viper-mobile-spyware/
- https://www.sentinelone.com/labs/arid-viper-apts-nest-of-spyc23-malware-continues-to-target-android-devices/
- https://www.security.com/threat-intelligence/mantis-palestinian-attacks
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1583/006/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1505/003/
