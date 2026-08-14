# 🛡️ Building a SOC Lab: Sentinel Analytics Rules & SOAR Automation

![Azure](https://img.shields.io/badge/Azure-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Kusto%20Query%20Language-blue)
![Logic%20Apps](https://img.shields.io/badge/Logic%20Apps-SOAR-orange)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

**Episode 5 of an 8-part SOC portfolio lab series.** This lab builds two custom Analytics Rules in Microsoft Sentinel and a fully automated SOAR playbook that triages, comments, and notifies on incidents end to end, no manual step required.

> All tenant details are masked. Placeholder domain: `contoso.onmicrosoft.com`. Fictional lab user: `jsmith`. IP addresses used in the simulation are documentation-reserved ranges (RFC 5737), not real hosts.

---

## 📌 Overview

Episodes 1 through 4 covered detection and simulation across MDE, MDO, and MDI. This episode moves into **Microsoft Sentinel** itself:

1. Custom log ingestion into Sentinel via the Logs Ingestion API
2. Two Analytics Rules built on top of that data, one custom-table based and one native-connector based
3. A Logic App playbook that automates triage, commenting, and notification (SOAR)
4. Full validation of the detection-to-response loop inside the unified Defender portal

---

## 🏗️ Environment

| Resource | Name |
|---|---|
| Resource Group | `RG-SOC-Lab-Sentinel` (East US) |
| Log Analytics Workspace | `law-soc-lab-sentinel` |
| VM | `vm-soc-lab-sentinel01` (Windows Server 2022, powered off outside of lab sessions) |
| Data Collection Endpoint | `dce-soc-lab-sentinel` |
| Data Collection Rules | `dcr-signinlogs-custom`, `dcr-scheduled-task-detection` |
| Playbook | `pb-soc-lab-incident-notify-tag` |

![Resource Group Overview](screenshots/01-environment-setup/01-resource-group-overview.png)
![Sentinel Workspace Enabled](screenshots/01-environment-setup/02-sentinel-workspace-enabled.png)

**Note:** Sentinel is now managed from the unified Defender portal (`security.microsoft.com` → Microsoft Sentinel → Configuration), not the classic Azure Sentinel blade. Microsoft has been migrating workspaces to this experience, and it is the primary interface for anyone starting a new lab today.

---

## 🎯 Scenario 1: Impossible Travel (T1078 - Valid Accounts)

A custom table, `SigninLogsCustom_CL`, was created in the workspace via a Data Collection Endpoint and Data Collection Rule, authenticated through an App Registration granted the **Monitoring Metrics Publisher** role on the DCR.

A PowerShell script pushes two simulated sign-in events through the Logs Ingestion API: a legitimate login from Tampa, followed twelve minutes later by an "impossible" login from Singapore for the same user.

**Detection query** (self-join comparing consecutive sign-ins per user, flagging a country change inside a 60-minute window):

```kql
SigninLogsCustom_CL
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, City, Country
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevCountry = prev(Country), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| where Country != PrevCountry
| extend TimeDeltaMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDeltaMinutes < 60
| project UserPrincipalName, PrevCountry, Country, PrevTime, TimeGenerated, TimeDeltaMinutes
```

![Injected Sign-in Events](screenshots/02-impossible-travel/01-injected-events-log-analytics.png)

**Analytics Rule:** "Impossible Travel - Sign-in from Distant Locations", Severity Medium, Tactic Initial Access, Technique T1078, entity mapping on Account/UserPrincipalName.

![Analytics Rule Created](screenshots/02-impossible-travel/02-analytics-rule-created.png)

**Result:** Incident #851 fired, was investigated, and closed as Resolved, Classification True Positive.

![Incident Resolved](screenshots/02-impossible-travel/05-incident-resolved-final.png)

**Limitation documented:** because the source is a custom table rather than a native connector, the incident's Evidence tab stays empty ("No related evidence was found"), even though entity mapping still works correctly. Worth calling out as a known trade-off of custom ingestion rather than a bug.

---

## 🎯 Scenario 2: Scheduled Task Persistence (T1053.005 - Scheduled Task)

The lab VM's NSG was restricted to a single source IP (deliberately tighter than the open NSG used in Episode 4). Inside the VM, a scheduled task named `WindowsUpdateHelper` was registered to simulate a persistence mechanism disguised as a routine update process:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command Write-Host 'persistence-simulated'"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "WindowsUpdateHelper" -Action $action -Trigger $trigger -Description "Simulated persistence task for SOC lab"
```

This generates Windows Security Event ID 4698.

### Troubleshooting the AMA pipeline

Getting this event into Sentinel was the most involved part of the episode:

1. A manual DCR (`dcr-scheduled-task-detection`) was built with a custom XPath filter (`Security!*[System[(EventID=4698)]]`), no DCE needed since this uses AMA directly rather than the Logs Ingestion API.
2. The Azure Monitor Agent installed cleanly, but no data was arriving.

![AMA Agent Installed](screenshots/04-troubleshooting-ama/01-ama-agent-installed.png)

3. Ruled out one by one: audit policy (already Success and Failure), managed identity (already on), network connectivity (`Test-NetConnection` succeeded), agent processes (all running).
4. Found the root cause: the manual DCR was mapped to the `Microsoft-Event` stream (table `Event`), not `Microsoft-SecurityEvent` (table `SecurityEvent`) as expected.
5. Agent logs on the VM confirmed a clean startup with the DCR downloaded and parsed correctly, ruling out an agent-side failure.
6. **Fix:** replaced the manual DCR approach with Sentinel's native **"Windows Security Events via AMA"** data connector (via Content Hub), which provisions its own DCR and event set, including 4698 under the "Common" event set.
7. Even with the native connector, data still landed in the `Event` table, likely due to overlap with the earlier manual DCR. Rather than chase the "textbook" `SecurityEvent` table, the pragmatic call was to build detection on `Event`, which was consistently reliable.
8. Minor gotcha: `Computer` is truncated to 15 characters (NetBIOS limit), so filters need to match the truncated hostname.

![AMA Connector Connected](screenshots/04-troubleshooting-ama/02-native-connector-installed.png)

**Detection query** (parses TaskName, ExecutedCommand, and ExecutedArgs out of the raw event description):

```kql
Event
| where EventID == 4698
| where Computer contains "vm-soc-lab-sent"
| extend TaskName = extract(@"<URI>\\?([^<]+)</URI>", 1, RenderedDescription)
| extend ExecutedCommand = extract(@"<Command>([^<]+)</Command>", 1, RenderedDescription)
| extend ExecutedArgs = extract(@"<Arguments>([^<]+)</Arguments>", 1, RenderedDescription)
| project TimeGenerated, Computer, TaskName, ExecutedCommand, ExecutedArgs
| order by TimeGenerated desc
```

**Analytics Rule:** "Scheduled Task Persistence - Suspicious Task Creation", Severity Medium, Tactic Persistence, Technique T1053.005, entity mapping on Host/Computer.

![Analytics Rule Review Detail](screenshots/03-scheduled-task-persistence/04-analytics-rule-review-detail.png)
![Both Analytics Rules Active](screenshots/03-scheduled-task-persistence/05-analytics-rules-both-active.png)

**Result:** Incident #434, *Scheduled Task Persistence - Suspicious Task Creation*, fired against `vm-soc-lab-sentinel`. The rule generated four incidents total across repeated evaluation cycles on the same underlying events, a known grouping/tuning gap worth documenting rather than hiding.

![Incident Detail](screenshots/03-scheduled-task-persistence/06-incident-detail.png)

Across both scenarios, the incident queue reached 11 total incidents over the course of testing, most of them duplicates from the same tuning gap described above.

![Both Scenarios Incident Queue](screenshots/06-bonus/01-both-scenarios-incidents-list.png)

---

## 🤖 SOAR Automation

The Logic App `pb-soc-lab-incident-notify-tag` runs on the Consumption plan and triggers on new Sentinel incidents, running three actions in sequence:

1. **Update incident** — adds an `Auto-Triaged` tag
2. **Add comment to incident (V3)** — posts a dynamic comment with Incident, Severity, Tactics, and Status
3. **Send an email (V2)** — notifies the analyst

![Logic App Full Flow](screenshots/05-playbook-soar/01-logic-app-designer-full-flow.png)
![Update Incident Action Configured](screenshots/05-playbook-soar/02-update-incident-action-configured.png)

A system-assigned managed identity on the Logic App was granted the **Microsoft Sentinel Responder** role on the workspace, which the Update incident and Add comment actions rely on.

Automation Rules connect the playbook to both Analytics Rules so it fires on either scenario.

### Notification channel

Email is sent via the **Office 365 Outlook** connector. Gmail was tried first, but Google blocks the Gmail connector from being used alongside the Microsoft Sentinel connector in the same workflow for personal accounts, citing a data-sharing policy violation. Switching to a dedicated Outlook.com account resolved it.

### Troubleshooting the playbook

- An `Unauthorized` error on the Update incident action turned out to be a cached token issued before the new IAM role had propagated. Reauthenticating the Sentinel connection with OAuth, and explicitly setting the workspace's Resource URI, fixed it.
- Safari blocked or blanked the nested OAuth popups needed for both the Microsoft and Outlook connections. Chrome handled these consistently.

**Confirmed working end to end:** across multiple test runs, the playbook applied the `Auto-Triaged` tag, posted the automated comment, and delivered the email notification with Incident, Severity, and Tactics (rendered as an array, e.g. `["InitialAccess"]`) and Status.

![Incident List Auto-Triaged](screenshots/05-playbook-soar/05-incident-list-autotriaged.png)
![Email Notification Received](screenshots/05-playbook-soar/06-email-notification-received.png)

---

## 🔧 Troubleshooting Log

| Issue | Cause | Fix |
|---|---|---|
| `InvalidToken` on Logs Ingestion API | Used the Client Secret ID instead of the Secret Value | Generated a new secret and used the Value |
| Analytics Rule not firing on schedule | Rule frequency set to 5 hours instead of 5 minutes | Corrected the schedule; one rule had to be deleted and recreated since the old scheduler did not recalculate correctly after the frequency change |
| Injected events missing from incidents | 24-hour lookback window expired if the injection script was not rerun the same day | Rerun the injection script on the day the incident needs to be generated |
| No data via manual DCR for Windows Security Events | DCR mapped to the `Event` stream, not `SecurityEvent` | Switched to the native "Windows Security Events via AMA" connector |
| Gmail connector blocked | Google policy blocks Gmail + Sentinel connectors together on personal accounts | Used a dedicated Outlook.com account with the Office 365 Outlook connector |
| `Unauthorized` on Update incident action | Cached OAuth token issued before the new role assignment propagated | Reauthenticated with OAuth and set the Resource URI explicitly |
| OAuth popups failing | Safari blocked nested authentication popups | Completed OAuth flows in Chrome |

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID | Scenario |
|---|---|---|
| Valid Accounts | T1078 | Impossible Travel |
| Scheduled Task | T1053.005 | Scheduled Task Persistence |

---

## 💡 Key Takeaways

- New Sentinel workspaces live under the **unified Defender portal** now, which is worth building muscle memory for instead of the classic Azure blade.
- The **native AMA connector** for Windows Security Events is more reliable than hand-building a DCR for standard event log ingestion, even when the resulting table (`Event` vs `SecurityEvent`) is not the one you originally expected.
- Custom-table ingestion via the Logs Ingestion API works well for simulation, but comes with real trade-offs, like an empty Evidence tab on resulting incidents.
- SOAR value does not require complexity. Tag, comment, notify is enough to remove the manual triage step entirely.
- A ransomware simulation (mass file rename pattern detection) surfaced as a strong candidate for a future standalone lab.

---

## 📁 Repository Structure

```
screenshots/
├── 01-environment-setup/
├── 02-impossible-travel/
├── 03-scheduled-task-persistence/
├── 04-troubleshooting-ama/
├── 05-playbook-soar/
└── 06-bonus/
```

---

## ⚠️ Disclaimer

This lab was built entirely in an isolated Azure trial environment for educational and portfolio purposes. No production systems, real user data, or real organizational assets were involved.

---

## 👤 Author

**Guillermo Costa** — Cybersecurity Analyst
[LinkedIn](https://linkedin.com/in/guillermo-costa) · [GitHub](https://github.com/GjcCS)
