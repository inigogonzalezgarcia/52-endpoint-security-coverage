# Data format

Put the files in one folder and run `python -m endpointcoverage review <folder>`. `inventory.csv`, `intune.csv` and `defender.csv` are required; every other file adds its checks (a control without its file is skipped, not passed). Comma, semicolon or tab separated, UTF-8. Column names are matched loosely (case, accents and punctuation are ignored), and the alternatives below are accepted, so the exports of the Intune and Defender portals load as they are. Dates as ISO 8601 (`2026-11-13`, `2026-11-12T08:00:00Z`), `dd/mm/yyyy`, `MM/dd/yyyy` or `13 Nov 2026`; the time zone suffix is ignored. Device names are compared by their short name in upper case (`tsa-mad-l0001.tailspin-aero.example` = `TSA-MAD-L0001`), serial numbers in upper case and Entra device IDs in lower case without braces.

`inventory.csv` comes from the CMDB or the asset register; `intune.csv`, `recovery-keys.csv` and, from the files you export, `defender.csv` and `local-admins.csv` from `scripts/Collect-EndpointCoverage.ps1`; `epm-elevations.csv` is the Endpoint Privilege Management elevation report exported from the Intune admin center; `exceptions.csv` is the exceptions register; `previous-coverage.csv` is last month's `coverage-summary.csv`.

## How the review works

| Step | Rule |
|---|---|
| One list | The inventory first; Intune records are matched to it by serial number, then by name; Defender records to those by Entra device ID, then by name. A device enrolled twice keeps its most recent Intune record |
| Scope | Windows and macOS devices with inventory status *In use* (or empty), plus devices active in Intune or Defender that the inventory does not have. Out of scope: other platforms (phones and tablets), devices *In stock*, and *Retired* ones, which are checked only to see whether they are still active |
| Status | Per device and control: `pass`, `fail`, `exception` (a fail covered by a valid exception) or `unknown` (no data for that control, for example a device that is not in the local admin report). `n/a` when the control does not apply to the platform |
| Coverage % | (pass + exception) / (pass + fail + exception) per control; unknown is not counted. *Fully protected*: in scope and no control failed |
| Exceptions | Valid when they have an approver, a ticket and an expiry date that has not passed; *expiring* within `exception_warning_days` (30) still counts. Incomplete or expired exceptions do not count |
| Severity | RED: devices in use not managed, managed devices not onboarded to Defender, devices not encrypted, real-time protection off, standing local admins, unsupported OS, an expired exception on MDM, EDR, encryption, local admin or OS, a control below `red_pct` (90). Everything else AMBER. The review is RED with any RED finding |
| Due dates | RED actions `action_days.red` (7) days from the review date, AMBER `action_days.amber` (30) |

## The controls

| Control | Platform | Passes when |
|---|---|---|
| `MDM` | all | The device has an Intune record |
| `COMPLIANT` | all | `complianceState` is compliant (in grace period is a fail) |
| `CHECKIN` | all | Last Intune check-in within `checkin_days` (14) |
| `ENCRYPTED` | all | `isEncrypted` is true (BitLocker on Windows, FileVault on macOS) |
| `KEY` | Windows | An operating system volume key (`volumeType` 1) exists in Entra ID for the device's Entra device ID. Unknown when the device is not encrypted |
| `EDR` | all | In Defender, onboarded, health *Active* and last report within `sensor_days` (7) |
| `AV` | Windows | Real-time protection on, signatures not overdue and tamper protection on (Intune `windowsProtectionState`). Skipped when `intune.csv` has none of these columns |
| `ADMIN` | Windows | Every member of the local Administrators group is in `allowed_admins` (by full or short name), or is the built-in account (SID ending in -500) |
| `OS` | all | `osVersion` at or above `min_os` for the platform (Windows `10.0.22631`, macOS `14.0` by default) |

## inventory.csv

| Column | Alternatives | Notes |
|---|---|---|
| Device | Device name, Hostname, Computer, Name | Required, or Serial |
| Serial | Serial number, Service tag | Used to match Intune |
| AssetTag | Asset tag, Asset id | |
| Platform | OS, Operating system | `Windows`, `macOS`, `iOS`… |
| Model | Device model | |
| Site | Location, Office | |
| Department | Cost centre, Business unit, Team | |
| User | Assigned to, Primary user, Email | |
| Status | State, Lifecycle | *In use*, *Deployed*, *Active* are in scope; *In stock*; *Retired*, *Disposed*, *Lost*, *Stolen* are retired |

## intune.csv

From `Get-MgDeviceManagementManagedDevice`, or the device export of the Intune admin center.

| Column | Alternatives |
|---|---|
| deviceName | Device name |
| serialNumber | Serial number |
| azureADDeviceId | Microsoft Entra Device ID, Entra device ID |
| operatingSystem | OS |
| osVersion | OS version |
| complianceState | Compliance |
| isEncrypted | Encrypted |
| lastSyncDateTime | Last check-in |
| userPrincipalName | Primary user UPN |
| managedDeviceOwnerType | Ownership |
| realTimeProtectionEnabled, signatureUpdateOverdue, tamperProtectionEnabled | Windows only, from `windowsProtectionState`; optional |

## defender.csv

The device inventory export of the Defender portal (Assets > Devices > Export), or the `machines` API.

| Column | Alternatives |
|---|---|
| computerDnsName | Device Name |
| aadDeviceId | Aad Device Id, Microsoft Entra Device ID |
| onboardingStatus | Onboarding Status (`Onboarded`, `CanBeOnboarded`, `Unsupported`, `InsufficientInfo`) |
| healthStatus | Health Status, Sensor health state (`Active`, `Inactive`, `ImpairedCommunication`, `NoSensorData`…) |
| lastSeen | Last Seen, Last device update |
| osPlatform | OS Platform |

## recovery-keys.csv

From `Get-MgInformationProtectionBitlockerRecoveryKey` (`id`, `deviceId`, `volumeType`, `createdDateTime`). Never the key itself: the list does not return it, and the review only needs to know that it exists.

## local-admins.csv

| Column | Alternatives | Notes |
|---|---|---|
| Device | Device name, Computer | |
| Account | Member, Principal | `DOMAIN\name` or `COMPUTER\name` |
| Type | Object class | User or Group |

`scripts/Detect-LocalAdmins.ps1` is an Intune Remediations detection script that writes the members as one line; `Collect-EndpointCoverage.ps1 -RemediationCsv` turns the remediation's device status export into this file. A Windows device missing from it is *unknown* for `ADMIN`.

## epm-elevations.csv

The elevation report of Endpoint Privilege Management, exported from the Intune admin center.

| Column | Alternatives |
|---|---|
| Device | Device name |
| User | UPN, Elevated by |
| File | File name, Application |
| Publisher | Signer |
| Elevation type | Type (`Automatic`, `User confirmed`, `Support approved`…) |
| Result | Outcome |
| Date | Time, Elevation time |

A file elevated successfully by at least `epm_rule_users` (5) users, never by an automatic rule, is a candidate for an automatic rule (`EPM-RULE`). A file elevated with no publisher is `EPM-UNSIGNED`.

## exceptions.csv

| Column | Alternatives | Notes |
|---|---|---|
| Device | Hostname, Scope | |
| Control | Control id, Check | One of the control codes above |
| Reason | Justification | |
| Approver | Approved by, Risk owner | Required for the exception to count |
| Ticket | Change, Risk id | Required |
| Expires | Expiry date, Valid until | Required |

## previous-coverage.csv

Last month's `coverage-summary.csv`: `control`, `coverage_pct` (and `FULL` for fully protected). Only used for the trend.

## settings.json

| Key | Default | Meaning |
|---|---|---|
| `organisation` | Endpoint estate | Title of the report |
| `review_date`, `previous_review` | now, – | Review date (the report is reproducible with it) |
| `target_pct`, `targets` | 98, {} | Target coverage, and per control (`{"EDR": 99}`) |
| `red_pct` | 90 | Below it a control is RED |
| `checkin_days`, `sensor_days` | 14, 7 | Freshness of Intune and Defender |
| `exception_warning_days` | 30 | Expiring window |
| `min_os` | Windows `10.0.22631`, macOS `14.0` | Minimum OS version per platform |
| `allowed_admins` | Administrator, Domain Admins, Device administrators | Members allowed in the local Administrators group |
| `epm_rule_users` | 5 | Users per file for a candidate rule |
| `action_days` | red 7, amber 30 | Days to the due date |
| `owners` | per control and area | `MDM`, `COMPLIANT`, `CHECKIN`, `ENCRYPTED`, `KEY`, `EDR`, `AV`, `ADMIN`, `OS`, `EPM`, `INVENTORY`, `EXCEPTIONS`, `COVERAGE` |
