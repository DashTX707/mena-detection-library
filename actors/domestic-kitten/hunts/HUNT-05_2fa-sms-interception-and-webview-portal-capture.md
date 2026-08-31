# Hunt: Google 2FA SMS interception and WebView portal credential capture

- **Hypothesis:** If the Rampant Kitten Android backdoor has interposed on a user's authentication, then the identity/account side will show the tell-tales of SMS-2FA theft and WebView phishing — Google/Telegram sign-ins from an unfamiliar device or geoinfeasible location shortly after a phishing-page visit, successful logins where the SMS OTP was never consumed by the legitimate handset, and account-recovery/2FA prompts the user did not initiate (a geoinfeasibility + unexpected-relationship anomaly).
- **ATT&CK:**
  - T1111 — Multi-Factor Authentication Interception (credential-access)
  - T1056.003 — Input Capture: Web Portal Capture (credential-access)
- **Actor procedure:** The Rampant Kitten Android backdoor intercepts incoming SMS and forwards any message whose body begins with `G-` (Google 2FA codes) to an attacker-controlled number, defeating SMS-based 2FA. It phishes Google credentials via a WebView with a `JavascriptInterface` bridge that captures the typed username/password; separately, fake Telegram "service" pages (`telegramreport.me`, `telegramco.org`, `telegrambots.me`) harvest Telegram credentials.
- **Why a hunt, not a rule:** SMS interception/forwarding and in-app WebView capture happen on the personal device with zero enterprise telemetry, so there is nothing on the endpoint to alert on — the only observable is the downstream account anomaly, which is inherently correlative and context-dependent (a new-device login is normal for travelers). This is an investigative correlation across identity logs, not a precise rule; the practical signals are account-side plus phishing-domain intelligence.
- **Visibility gap:** The device-side SMS-forwarding event and the WebView capture are unobservable to the enterprise. That gap is itself a finding — flag it and recommend hardware-key / app-based MFA to remove the SMS-2FA weakness the actor exploits.

## Data sources required

- Identity-provider sign-in logs (Entra ID / Google Workspace: user, device, IP, geo, MFA method, result)
- MFA/OTP delivery logs (SMS OTP issued vs. consumed, where available)
- Proxy/DNS logs (visits to Telegram/Google phishing lookalikes — pivot from HUNT-01)
- User-reported "I got a 2FA prompt I didn't ask for" / spurious-notification reports

## Query starting point

Platform: `Microsoft Sentinel / Entra ID KQL`

```kql
// Successful MFA sign-ins from a new device/geo shortly after a phishing-domain visit
let phish_hits = CommonSecurityLog
| where RequestURL has_any ("telegramreport","telegramco","telegrambots","mailgoogle","gradleservice")
| project PhishTime=TimeGenerated, SourceUserName, SourceIP;
SigninLogs
| where ResultType == 0 and AuthenticationRequirement == "multiFactorAuthentication"
| extend mfaMethod = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| where mfaMethod has_any ("SMS","text message","Mobile phone")
| join kind=leftouter (phish_hits) on $left.UserPrincipalName == $right.SourceUserName
| extend newDevice = isempty(DeviceDetail.deviceId)
| summarize signins=count(), countries=make_set(Location), ips=make_set(IPAddress),
    lastPhish=max(PhishTime) by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(countries) > 1 or isnotempty(lastPhish)
| sort by signins desc
```

## Triage guidance

- **Likely malicious:** Successful SMS-2FA sign-in from a device/country the user has never used, within hours of a visit to a Telegram/Google phishing lookalike; an OTP issued to the user's number but the login originates elsewhere; user reports a 2FA code or "Google protect is enabled" notification they did not trigger.
- **Likely benign:** Legitimate travel/roaming with a corroborating itinerary; a genuine new-device enrollment the user confirms; corporate VPN egress that shifts apparent geo. Baseline the user's normal device/geo set.
- **Pivot next:** Reset credentials and revoke sessions/tokens for the affected account, move it off SMS-2FA to FIDO2/app-based MFA, and pivot to HUNT-01 for the phishing-domain infrastructure. Confirmed account takeover is an incident — **escalate to incident-response**.

## References

- https://research.checkpoint.com/2020/rampant-kitten-an-iranian-espionage-campaign/
- https://attack.mitre.org/techniques/T1111/
- https://attack.mitre.org/techniques/T1056/003/
