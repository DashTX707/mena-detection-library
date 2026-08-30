# Hunt: Predatory Sparrow — destructive financial-impact staging (crypto-burn & banking data destruction)

- **Hypothesis:** This actor's "financial" impact is **destruction, not theft** — it burned ~$90M from the Nobitex exchange to provably-unspendable vanity addresses and destroyed banking data at Bank Sepah rather than stealing for profit (T1657). The on-chain burn and the banking-data destruction are largely observed *off-victim* (chain analysis, victim disclosure), so this hunt is **intel-led with a defender-side operational-technology / financial-systems angle**: if a bank, exchange, payment processor, or fintech in our remit is being staged for this actor's destructive-financial pattern, the tells are (1) **enterprise/OT-adjacent access to the systems that hold value-bearing state** — core banking DBs, wallet/HSM/key-management hosts, exchange hot-wallet servers, payment-switch/settlement systems — by identities that should never touch them, and (2) **off-victim chain/OSINT signals** — actor-claimed or chain-analysis-flagged burns to null/vanity addresses, or persona teasers naming a financial target. The finding is the **conjunction**: unexpected privileged access to a value-bearing system on-victim, corroborated by chain-analysis/persona intel that this actor is targeting that institution. A destructive-financial operation looks like a wipe of the *right* servers, not a fraud pattern.
- **ATT&CK:**
  - T1657 — Financial Theft (impact) — the actor destroyed Bank Sepah banking data and burned ~$90M of Nobitex crypto to unspendable "vanity" addresses (destruction-not-theft, message-driven); hunt on-victim access to value-bearing systems plus off-victim chain/disclosure intel.

- **Actor procedure:** During the June 2025 Israel-Iran conflict the actor claimed a **destructive attack on state-owned Bank Sepah** (asserting the bank funded the Iranian military and destroying its banking data), and the next day **drained/burned ~$90M from the Nobitex crypto exchange by sending assets to provably-unspendable vanity "burn" addresses** — deliberately *not* stealing them, to send a message rather than profit; chain-analysis firms corroborated the movement. This is financially-themed *impact*, executed with the same destructive playbook as the wiper operations (data destruction, recovery denial) but aimed at value-bearing systems. Because the decisive act is on the blockchain or in the bank's own core, the richest evidence is off-victim (chain analysis, victim disclosure, the actor's Telegram claim) — but the *access* to hot-wallet/key-management/core-banking hosts that enables it is on-victim and huntable in the staging window.

- **Why a hunt, not a rule:** The burn itself happens on a public blockchain and the banking destruction is disclosed by the victim — neither is an event in a defender's SIEM, so there is nothing to alert on at the impact step. On-victim, "an admin logged into the core-banking DB" or "a process touched the wallet host" are legitimate operations; only the **conjunction** of unexpected privileged access to a value-bearing system with **external intel** (chain-analysis burn flags, persona targeting) distinguishes staging from routine finance operations. That fusion of financial-systems context, identity analytics, and off-victim intel is hunt work — and for firms *without* crypto/banking assets, this hunt is explicitly an **intel/monitoring** posture (watch chain-analysis and disclosure feeds), not a host hunt. Nothing here is a standalone rule.

## Data sources required

- Identity/auth analytics on value-bearing systems: core-banking DB servers, payment-switch/settlement hosts, exchange hot-wallet servers, HSM/key-management appliances — privileged logons by identity, source, and hour (the on-victim staging half)
- Off-victim chain-analysis & disclosure intel: chain-analysis provider feeds (Chainalysis/TRM/Elliptic) flagging transfers to null/vanity/burn addresses tied to our institution's wallets; victim-disclosure and regulator/CERT notifications
- Persona/OSINT monitoring (shared with HUNT-04): actor Telegram/social claims or teasers naming a financial/exchange target
- Wallet/settlement transaction-integrity monitoring where it exists (anomalous outbound to non-whitelisted addresses; mass-destination sends) — and where it does not, a documented visibility gap

## Query starting point

Platform: `Splunk SPL` — surface unexpected privileged access to value-bearing systems, to be fused with chain-analysis/persona intel

```spl
index=wineventlog EventCode IN (4624,4672,4648)
  (ComputerName IN (CORE_BANKING_HOSTS, PAYMENT_SWITCH_HOSTS, HOTWALLET_HOSTS, HSM_KMS_HOSTS))
| eval value_system=case(
      like(ComputerName,"%wallet%"),"hot_wallet",
      like(ComputerName,"%hsm%") OR like(ComputerName,"%kms%"),"key_mgmt",
      like(ComputerName,"%switch%") OR like(ComputerName,"%settle%"),"payment_switch",
      1=1,"core_banking")
| lookup approved_admins_by_system value_system Account OUTPUT is_approved
| where isnull(is_approved) OR is_approved!="yes"       /* identity not on the value-system allow-list */
| eval offhours=if(date_hour<6 OR date_hour>21,1,0)
| stats values(value_system) as systems values(ComputerName) as hosts
        values(Logon_Type) as logon_types sum(offhours) as offhours_logons
        min(_time) as first max(_time) as last count by Account, src_ip
| where systems!="" 
| convert ctime(first) ctime(last)
| sort - count
/* Fuse the result with: (1) chain-analysis feed flagging burns/vanity-address sends tied to our wallets,
   and (2) persona OSINT naming our institution. On-victim access alone is a lead; access + external
   corroboration is the finding. */
```

## Triage guidance

- **Likely malicious:** a privileged logon to a hot-wallet, HSM/KMS, payment-switch, or core-banking host by an identity not on that system's allow-list — off-hours, from a new source — especially when a chain-analysis feed simultaneously flags transfers from our wallets to null/vanity/burn addresses or the actor's persona names our institution; any mass-destination or non-whitelisted-address send from a wallet system; destruction-pattern activity (mass deletion, shadow-copy/backup sabotage — cross-ref destructive lane T1485/T1490) on a value-bearing server rather than a fraud/withdrawal pattern.
- **Likely benign / expected:** DBAs, treasury/settlement operators, and wallet/HSM administrators legitimately access these systems on schedule — baseline the approved admins per system in `approved_admins_by_system`; scheduled settlement, reconciliation, and key-ceremony activity is expected; a single chain-analysis alert may be an ordinary internal transfer. The differentiator is **allow-list violation + off-hours/new-source + external corroboration**, not any single access.
- **Pivot next:** on-victim value-system access with external (chain-analysis or persona) corroboration is a destructive-financial operation in progress — escalate to incident-response-coordinator immediately, freeze/rotate wallet keys and settlement credentials, preserve on-chain and host evidence for chain-analysis and regulator notification, and run the destructive-detection lane on the value-bearing hosts (this actor destroys rather than steals, so expect a wipe, not a withdrawal). For firms with **no** crypto/banking assets, treat this hunt as a standing intel-monitoring posture and route persona/chain findings to cti-expert rather than a host investigation.

## References

- https://en.wikipedia.org/wiki/Predatory_Sparrow
- https://www.cnbc.com/2023/12/18/pro-israel-hackers-claim-cyberattack-disrupting-irans-gas-stations.html
- https://attack.mitre.org/techniques/T1657/
