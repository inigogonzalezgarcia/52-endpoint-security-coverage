# Monthly endpoint security coverage review

## The cycle

1. **First working day of the month.** Run the collector, export the Defender device inventory, the remediation status of `Detect-LocalAdmins` and the EPM elevation report, and refresh `inventory.csv` from the CMDB. Copy last month's `coverage-summary.csv` to `previous-coverage.csv`.
2. **Build the outputs** (`python -m endpointcoverage review data/`) and read `report.html` top to bottom.
3. **Before the meeting.** Open the RED actions as tickets with their owner and due date; check each decision has the facts it needs.
4. **The review** (30 minutes: endpoint team, security operations, the asset manager and the head of IT). Go through the decisions, agree owners and dates, approve or refuse exceptions. Fill in the `[TO COMPLETE]` sections of `review-pack.md` and keep it with the outputs.
5. **During the month.** Close the actions; re-run the review on the fixed devices before marking them done.

## How to read the result

- **Start with the reconciliation.** A device in use that is in no tool is the biggest gap: nothing protects or reports on it. Devices in Intune or Defender that the inventory does not have are next, because nobody owns them. Retired devices that still check in are either not retired or not wiped.
- **Then the RED controls.** Not managed, no working EDR, not encrypted, real-time protection off, standing admins, unsupported OS. Each is a short list of named devices.
- **Then look for the cause, not the device.** Gaps cluster: one department, one site, one model, one build process. Six workstations missing from Defender usually mean one group missing from the onboarding policy; eleven keys missing usually mean one imaging process. Fix the cause, and the devices follow.
- **Compliance follows the rest.** Most noncompliant devices are already in another finding; work the ones that are not.
- **The trend.** One bad month is a backlog; three in a row is a process problem.

## Fix, exception or decision

| Situation | Usual answer |
|---|---|
| A device not enrolled, not onboarded, not encrypted | Fix this week. Block it from company data (Conditional Access) or the network if it is not fixed by the due date |
| Real-time protection off for an application | Turn it back on; give the application a scoped exclusion approved by security |
| Standing local admin | Remove it in one change, after the EPM rules cover what the users need |
| The same installer approved for many users | An automatic EPM rule by file and publisher, scoped to the group that uses it, reviewed in six months |
| An unsigned tool elevated | Find its owner. Sign it, allow it by hash with an owner, or block it |
| A device that cannot be upgraded (certified equipment) | A time-limited exception with an approver, a ticket and an end date, and compensating controls (isolated network, no email or browsing) |
| A device that cannot run the EDR sensor | Same, with the bench or system owner as the monitoring owner |

An exception is a decision with an end date, not a status. Expired exceptions are RED on the high controls so they come back to the meeting.

## Audit evidence (ISO 27001, NIS2)

Each month keep the outputs and the completed pack together. They show:

- an asset inventory reconciled with the management and security tools (`reconciliation.csv`);
- the coverage of each control on each device, and its trend (`device-coverage.csv`, `coverage-summary.csv`);
- the gaps with their causes, owners and due dates (`gaps.csv`, `actions.csv`);
- privileged access on endpoints and how elevation is controlled (`elevations-review.csv`);
- the exceptions register with approver, ticket and expiry (`exceptions-review.csv`);
- the decisions taken (`review-pack.md`).

## Before changing a policy

- Pilot onboarding, encryption and account protection changes on a test ring first, and watch the Intune and Defender reports for a few days.
- Remove local admin rights in waves, starting with the users who have EPM rules ready.
- Agree with the service desk before an automatic elevation rule goes live: it removes tickets, and they should know which.
