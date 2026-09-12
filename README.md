# Identity Access Management (IAM)

<p align="center">
<img width="3258" height="1086" alt="image" src="https://github.com/user-attachments/assets/46176870-84b1-492b-a73d-b6b1bf991bd9" />
</p>

## Project Flow:
```python
	Identity → Authentication → Authorization → Privileged Access → Monitoring → Detection → Response → Automate
```

# Implementing Identity and Access Management (IAM)

Implementing Identity and Access Management (IAM) is essential for protecting organizational resources, enforcing least privilege, reducing unauthorized access, and supporting regulatory compliance. 
An effective IAM program establishes controls across the complete identity lifecycle—from identity creation and authentication through authorization, governance, monitoring, and eventual de-provisioning.

## 1. Define the IAM Strategy
Establish the objectives and scope of the IAM program before implementing technical controls.

* Identify key stakeholders across IT, cybersecurity, compliance, and business units.
* Define IAM objectives aligned with organizational and security requirements.
* Establish requirements for authentication, authorization, identity lifecycle management, and governance.
* Develop an IAM roadmap defining implementation phases, priorities, resources, and timelines.
* Identify regulatory and compliance requirements that influence identity controls.

A clearly defined strategy helps prevent fragmented access policies and inconsistent security controls.


## 2. Assess the Current Security Posture
Evaluate the existing identity environment to establish a security baseline and identify access-related risks.

* Inventory identities, accounts, roles, groups, applications, and privileged accounts.
* Review existing authentication and authorization controls.
* Identify excessive permissions, dormant accounts, orphaned identities, and privilege escalation risks.
* Review current provisioning and de-provisioning processes.
* Classify systems and data according to sensitivity and business impact.
* Evaluate whether CIEM capabilities are required for complex cloud environments.

The assessment establishes the gap between the current environment and the desired IAM security posture.


## 3. Design Access and Authentication Policies
Define how identities authenticate and what resources they are permitted to access.

* Implement Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) where appropriate.
* Apply the principle of least privilege.
* Enforce Multi-Factor Authentication (MFA) for sensitive and privileged access.
* Establish Conditional Access or equivalent risk-based access controls.
* Separate standard user and administrative privileges.
* Define privileged-access requirements and approval processes.
* Align authentication and identity assurance requirements with applicable standards such as NIST SP 800-63.

Access should be granted according to demonstrated business requirements rather than convenience.


## 4. Select and Deploy the IAM Architecture
Determine how IAM services will operate across the organization's technology environment.

* Select cloud, on-premises, or hybrid identity architecture based on business and security requirements.
* Implement centralized authentication and authorization where practical.
* Provide Single Sign-On (SSO) for approved applications.
* Integrate IAM with cloud infrastructure, SaaS applications, on-premises systems, and development environments.
* Implement privileged identity and access management controls.
* Validate interoperability across hybrid or multi-cloud environments.

Deployment should begin with a controlled pilot before expanding to production environments.


## 5. Integrate and Validate IAM Controls
Integrate the IAM platform with organizational systems and verify that security controls operate as intended.

* Connect applications, infrastructure, and security monitoring systems.
* Test authentication, authorization, SSO, and MFA.
* Verify RBAC/ABAC assignments and least-privilege enforcement.
* Test provisioning and de-provisioning workflows.
* Validate privileged-access restrictions.
* Test unauthorized and abnormal access scenarios.
* Provide user and administrator training before full deployment.

Testing should demonstrate not only that legitimate access succeeds, but also that unauthorized access is prevented and recorded.


## 6. Automate Identity Governance
Implement Identity Governance and Administration (IGA) to manage identities throughout their lifecycle.

* Automate user provisioning and de-provisioning.
* Establish Joiner, Mover, and Leaver (JML) processes.
* Conduct periodic access reviews and certifications.
* Automatically identify dormant or unnecessary accounts.
* Implement approval workflows for sensitive access.
* Review privileged-role assignments regularly.
* Maintain audit records of identity and access changes.

Automation reduces administrative error and limits the time unnecessary privileges remain active.


## 7. Monitor, Detect, and Continuously Improve

IAM security continues after deployment. Identity activity should be continuously monitored and controls adjusted as risks change.
The end goal is to automate as much as possible, with recurring analysis to update existing and new automation rules.

* Monitor authentication and authorization activity.
* Detect repeated authentication failures and MFA abuse.
* Identify anomalous sign-ins and impossible or unusual access patterns.
* Monitor privilege assignments and administrative-role changes.
* Detect unauthorized access attempts.
* Conduct periodic vulnerability assessments and penetration testing.
* Track IAM security metrics and Key Performance Indicators (KPIs).
* Measure time to provision, modify, and revoke access.
* Review access violations and identity-related security incidents.
* Continuously refine controls as threats, technology, and compliance requirements evolve.

Identity Security Posture Management (ISPM) can provide an additional continuous-assessment layer for identifying identity configuration weaknesses, excessive privileges, and emerging identity risks.

## IAM Implementation Lifecycle
```python
	PLAN → ASSESS → DESIGN → DEPLOY → GOVERN → MONITOR → IMPROVE → AUTOMATE
```

The objective is not to manage user accounts. A mature IAM implementation establishes a verifiable security model in which identities are authenticated appropriately, access is explicitly authorized, privileges are minimized, changes are governed, and identity activity produces sufficient evidence for investigation and audit.

That gives us a natural bridge from IAM administration → IAM security engineering → Sentinel/KQL detection rather than ending the project after configuring users, groups, and permissions.
	“Testing should demonstrate not only that legitimate access succeeds, but also that unauthorized access is prevented and recorded.”
	
# PYTHON DETECTION SCRIPTS

## 1. Detect Excessive Privileges
``` Python

user_roles = {
    "alice": ["read_reports"],
    "bob": ["read_reports", "edit_reports"],
    "charlie": ["read_reports", "edit_reports", "delete_reports", "admin"]
}

allowed_role_count = 2

for user, roles in user_roles.items():
    if len(roles) > allowed_role_count:
        print(f"[ALERT] {user} may have excessive privileges: {roles}")

This demonstrates least-privilege monitoring. Charlie has more permissions than the defined threshold and is flagged for review.
```

## 2. Detect Unauthorized Administrative Access
``` Python

authorized_admins = ["alice", "security_admin"]

login_events = [
    {"user": "alice", "role": "admin"},
    {"user": "bob", "role": "user"},
    {"user": "charlie", "role": "admin"}
]

for event in login_events:
    if event["role"] == "admin" and event["user"] not in authorized_admins:
        print(
            f"[ALERT] Unauthorized administrative access detected: "
            f"{event['user']}"
        )

This checks whether someone using an administrative role is actually on the approved administrator list.
```

## 3. Detect Repeated Failed Logins
``` Python

login_events = [
    {"user": "alice", "status": "failed"},
    {"user": "alice", "status": "failed"},
    {"user": "alice", "status": "failed"},
    {"user": "bob", "status": "success"}
]

failed_logins = {}

for event in login_events:
    if event["status"] == "failed":
        user = event["user"]
        failed_logins[user] = failed_logins.get(user, 0) + 1

for user, count in failed_logins.items():
    if count >= 3:
        print(
            f"[ALERT] Multiple failed authentication attempts: "
            f"{user} ({count} failures)"
        )

This models detection of password spraying, brute-force activity, or repeated authentication failures.
```

## 4. Detect Dormant Account Usage
``` Python

from datetime import datetime, timedelta

accounts = [
    {
        "user": "alice",
        "last_login": datetime.now() - timedelta(days=5)
    },
    {
        "user": "bob",
        "last_login": datetime.now() - timedelta(days=120)
    }
]

dormant_threshold = 90

for account in accounts:
    days_inactive = (datetime.now() - account["last_login"]).days

    if days_inactive > dormant_threshold:
        print(
            f"[ALERT] Dormant account detected: "
            f"{account['user']} inactive for {days_inactive} days"
        )

This supports Identity Governance and Administration (IGA) by identifying accounts that may need disabling or review.
```

## 5. Detect Privilege Escalation
``` Python

role_changes = [
    {
        "user": "alice",
        "old_role": "reader",
        "new_role": "reader"
    },
    {
        "user": "bob",
        "old_role": "reader",
        "new_role": "admin"
    }
]

privileged_roles = ["admin", "global_admin", "security_admin"]

for change in role_changes:
    if (
        change["new_role"] in privileged_roles
        and change["old_role"] not in privileged_roles
    ):
        print(
            f"[ALERT] Privilege escalation detected: "
            f"{change['user']} changed from "
            f"{change['old_role']} to {change['new_role']}"
        )

This one is particularly useful for a cybersecurity portfolio because it detects a security-relevant change, rather than just validating configuration.
```

## 6. Detect Disabled Account Authentication
``` Python

accounts = {
    "alice": "enabled",
    "bob": "disabled",
    "charlie": "enabled"
}

login_events = [
    {"user": "alice", "status": "success"},
    {"user": "bob", "status": "success"},
    {"user": "charlie", "status": "failed"}
]

for event in login_events:
    user = event["user"]

    if (
        accounts.get(user) == "disabled"
        and event["status"] == "success"
    ):
        print(
            f"[CRITICAL] Disabled account successfully authenticated: {user}"
        )

A disabled account successfully authenticating would warrant immediate investigation.
```

## 7. Detect MFA Fatigue Behavior
``` Python

mfa_events = [
    {"user": "alice", "result": "denied"},
    {"user": "alice", "result": "denied"},
    {"user": "alice", "result": "denied"},
    {"user": "alice", "result": "approved"},
    {"user": "bob", "result": "approved"}
]

mfa_denials = {}

for event in mfa_events:
    user = event["user"]

    if event["result"] == "denied":
        mfa_denials[user] = mfa_denials.get(user, 0) + 1

    if (
        event["result"] == "approved"
        and mfa_denials.get(user, 0) >= 3
    ):
        print(
            f"[ALERT] Possible MFA fatigue attack: "
            f"{user} approved MFA after "
            f"{mfa_denials[user]} denials"
        )

This is an especially strong IAM detection example because it connects authentication telemetry to attacker behavior.
```

## 8. Detect Access Outside Normal Role Permissions
This expands the original RBAC example into an actual detection control.
``` Python

role_permissions = {
    "analyst": ["read_reports"],
    "manager": ["read_reports", "edit_reports"],
    "admin": ["read_reports", "edit_reports", "delete_reports"]
}

users = {
    "alice": "analyst",
    "bob": "manager",
    "charlie": "admin"
}

activity_log = [
    {"user": "alice", "action": "read_reports"},
    {"user": "alice", "action": "delete_reports"},
    {"user": "bob", "action": "edit_reports"}
]

for event in activity_log:
    user = event["user"]
    action = event["action"]

    role = users.get(user)
    allowed_actions = role_permissions.get(role, [])

    if action not in allowed_actions:
        print(
            f"[ALERT] Unauthorized action detected: "
            f"{user} attempted '{action}' "
            f"with role '{role}'"
        )
```

This produces the kind of detection logic in the IAM project:
```python	
	Identity → Role → Expected Permission → Observed Action → Detection
```
```kql
Python IAM Detection Script Library:
	1. detect_excessive_privileges.py
	2. detect_unauthorized_admin.py
	3. detect_failed_logins.py
	4. detect_dormant_accounts.py
	5. detect_privilege_escalation.py
	6. detect_disabled_account_authentication.py
	7. detect_mfa_fatigue.py
	8. detect_rba_policy_violations.py
```
Each IAM security concept can be implemented first in Python and then translated into an equivalent Microsoft Sentinel KQL detection.
```python	
	Python logic → Enterprise telemetry → KQL detection rule
```

Underlying security logic remains consistent even when the implementation technology changes.
- **Security Concept:** Detect repeated failed authentications
- **Python:** Analyze authentication records, count failed attempts by user, and generate an alert when a defined threshold is exceeded.
- **Microsoft Sentinel / KQL:** Query `SigninLogs`, group failed authentication attempts by user and time window, and identify accounts exceeding the detection threshold.

The objective is to demonstrate:
```python	
	IAM Principle → Detection Logic → Python Implementation → KQL Implementation → Security Investigation
```

This provides flexibility across standalone applications, automation workflows, cloud environments, and enterprise SIEM platforms while preserving the same evidence-driven detection methodology.


# KQL DETECTION SCRIPTS

The following matching Microsoft Sentinel / KQL detection for the eight Python concepts.
Microsoft currently documents:
	• SigninLogs for authentication analysis
	• AuditLogs for identity/directory changes
	• AzureActivity for Azure resource operations.

## 1. Excessive Privileges: This looks for users receiving an unusually high number of role assignments.
```kql

AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any (
    "Add member to role",
    "Add eligible member to role",
    "Add member to directory role"
)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].displayName)
| where isnotempty(TargetUser)
| summarize
    RoleAssignmentCount = count(),
    Roles = make_set(RoleName)
    by TargetUser
| where RoleAssignmentCount >= 3 //Per users role
| order by RoleAssignmentCount desc
```
Detection logic:  User → Role assignments → Count privileges → Flag excessive access
The threshold of 3 is an example, not a universal definition of excessive privilege. In production, compare assignments against the user's expected role.


## 2. Unauthorized Administrative Access
Here we define an approved administrator baseline and detect privileged operations performed by anyone outside it.
```kql

let ApprovedAdmins = dynamic([
    "alice@contoso.com",
    "securityadmin@contoso.com"
]);

AuditLogs
| where TimeGenerated > ago(24h)
| extend Actor =
    tostring(InitiatedBy.user.userPrincipalName)
| where OperationName has_any (
    "Add member to role",
    "Remove member from role",
    "Reset user password",
    "Delete user",
    "Add service principal"
)
| where isnotempty(Actor)
| where Actor !in~ (ApprovedAdmins)
| project
    TimeGenerated,
    Actor,
    OperationName,
    TargetResources,
    Result
| order by TimeGenerated desc
```
This demonstrates an important IAM concept:
```YAML
Privileged action + actor not authorized = detection
```
Microsoft also uses `AuditLogs` to investigate sensitive administrative actions and possible privilege escalation.


## 3. Repeated Failed Authentication
This is the closest KQL equivalent to the Python failed-login counter.
```kql

SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    Applications = make_set(AppDisplayName),
    SourceIPs = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```
Here we're asking:
Which identity failed authentication five or more times within ten minutes?
Microsoft documents ResultType != 0 as a method for querying failed sign-ins.


## 4. Dormant Account Activity
This one is more interesting because merely finding a dormant account isn't the same as detecting activity from a dormant account.
```kql

let HistoricalSignins =
    SigninLogs
    | where TimeGenerated between (ago(120d) .. ago(30d))
    | where ResultType == 0
    | summarize LastHistoricalLogin = max(TimeGenerated)
        by UserPrincipalName;

let RecentSignins =
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == 0
    | summarize
        CurrentLogin = max(TimeGenerated),
        SourceIP = any(IPAddress),
        Application = any(AppDisplayName)
        by UserPrincipalName;

RecentSignins
| join kind=leftouter HistoricalSignins on UserPrincipalName
| extend DaysSincePreviousLogin =
    datetime_diff("day", CurrentLogin, LastHistoricalLogin)
| where DaysSincePreviousLogin >= 90
| project
    UserPrincipalName,
    LastHistoricalLogin,
    CurrentLogin,
    DaysSincePreviousLogin,
    SourceIP,
    Application
| order by DaysSincePreviousLogin desc
```

This detects something much more security-relevant:
- A previously inactive identity suddenly became active.
- Your actual usable lookback depends on how much SigninLogs history your workspace retains.


## 5. Privilege Escalation
A production design would only treat a privileged-role assignment as suspicious only when context increases the risk. 
That context can include whether the actor is an approved administrator, whether the change occurred through PIM, 
whether it happened during an approved change window, and whether the assignment was permanent or unexpected.
```kql

let ApprovedAdmins = dynamic([
    "securityadmin@contoso.com",
    "iamadmin@contoso.com"
]);

let PrivilegedRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "User Administrator"
]);

AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any (
    "Add member to role",
    "Add eligible member to role",
    "Add member to directory role"
)
| extend Actor =
    tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser =
    tostring(TargetResources[0].userPrincipalName)
| extend RoleName =
    tostring(TargetResources[0].displayName)
| where RoleName in~ (PrivilegedRoles)
| extend ApprovedAdministrator =
    Actor in~ (ApprovedAdmins)
| extend OutsideChangeWindow =
    hourofday(TimeGenerated) < 8
    or hourofday(TimeGenerated) > 18
| where
    ApprovedAdministrator == false
    or OutsideChangeWindow == true
| project
    TimeGenerated,
    Actor,
    TargetUser,
    RoleName,
    ApprovedAdministrator,
    OutsideChangeWindow,
    OperationName,
    Result
| order by TimeGenerated desc
```

Conceptually:
```kql
	Standard Identity → Privileged Role Assignment → Alert
```
For a production analytic, we'd enrich this with approved change windows, `Privileged Identity Management (PIM) activity`, and known administrators rather than treating every privileged assignment as malicious.

Now the logic is different:
	Privileged role assigned does not automatically equal malicious.

Instead:
```yaml
**Privileged role assignment
	• unexpected actor 
	• unusual timing 
	• no approved workflow
= higher-confidence privilege-escalation detection** 
```
- PIM makes this even stronger. 
- A normal PIM activation may be expected, while a direct permanent assignment to Global Administrator outside PIM would deserve substantially more scrutiny.


## 6. Disabled-Account Authentication
This is a good example of correlation, because SigninLogs alone doesn't establish when the account was disabled.
First identify account-disable activity, then look for a subsequent successful authentication.
```kql

let DisabledAccounts =
    AuditLogs
    | where TimeGenerated > ago(30d)
    | where OperationName == "Update user"
    | mv-expand Property = TargetResources[0].modifiedProperties
    | extend
        PropertyName = tostring(Property.displayName),
        NewValue = tostring(Property.newValue),
        DisabledUser =
            tostring(TargetResources[0].userPrincipalName)
    | where PropertyName == "AccountEnabled"
    | where NewValue contains "false"
    | summarize DisabledTime = max(TimeGenerated)
        by DisabledUser;

SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| join kind=inner DisabledAccounts
    on $left.UserPrincipalName == $right.DisabledUser
| where TimeGenerated > DisabledTime
| project
    TimeGenerated,
    UserPrincipalName,
    DisabledTime,
    IPAddress,
    AppDisplayName,
    Location
| order by TimeGenerated desc
```

- Microsoft's Sentinel account-action logic similarly uses `AuditLog`s and the `AccountEnabled` property to identify account-disable activity.
- This correlation is a particularly good portfolio example:
	```yaml
	Account disabled → later successful authentication → investigate
	```


## 7. MFA Fatigue
MFA fatigue detection looks for repeated multi-factor authentication challenges that may indicate an attacker is attempting to pressure a user into approving an unauthorized sign-in.
Microsoft `Entra sign-in logs` record MFA-related authentication failures in `SigninLogs`. 
A simple detection can identify users who experience multiple failed MFA challenges within a short period.

// Introductory Baseline
```kql
SigninLogs 
| where TimeGenerated > ago(1h)
| where ResultType == 50074
| summarize
    MFAFailures = count(),
    SourceIPs = make_set(IPAddress),
    Applications = make_set(AppDisplayName)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where MFAFailures >= 3
| order by MFAFailures desc
```

This query identifies users who experienced three or more failed MFA challenges within a ten-minute period.
The detection logic is:
```yaml
	Repeated MFA Failures → Identify User → Count Attempts → Flag Repeated Challenge Activity
```
However, repeated MFA failures alone do not prove an MFA fatigue attack. 
They may also result from user error, expired sessions, device issues, or legitimate authentication problems.

A stronger detection looks for a more meaningful behavioral sequence:
```yaml
	Repeated MFA Failures → Followed by Successful Authentication
```
// Primary Example
```kql
let MFAFailures =
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 50074
    | summarize
        FailureCount = count(),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by UserPrincipalName
    | where FailureCount >= 3;
let SuccessfulSignins =
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 0
    | project
        UserPrincipalName,
        SuccessfulLogin = TimeGenerated,
        IPAddress,
        AppDisplayName;
MFAFailures
| join kind=inner SuccessfulSignins on UserPrincipalName
| where SuccessfulLogin > LastFailure
| project
    UserPrincipalName,
    FailureCount,
    FirstFailure,
    LastFailure,
    SuccessfulLogin,
    IPAddress,
    AppDisplayName
| order by SuccessfulLogin desc
```

This second query correlates repeated failed MFA challenges with a later successful sign-in for the same identity.

The detection logic becomes:
	Repeated MFA Failures → Same Identity → Later Successful Sign-In → Investigate

This approach is stronger because it evaluates a `behavioral sequence` rather than a single error condition.

A successful sign-in following repeated MFA failures still does not automatically prove malicious activity. 
It indicates a higher-risk authentication pattern that should be investigated in context with source IP addresses, 
device information, application access, geographic location, Conditional Access results, and user-reported MFA activity.

## Detection Progression

```python
Basic Detection
Repeated MFA Failures
        ↓
Threshold Exceeded
        ↓
Potential MFA Abuse

Improved Detection
Repeated MFA Failures
        ↓
Successful Authentication
        ↓
Higher-Risk Behavioral Pattern
        ↓
Investigation
```

The important distinction is that the first query detects `authentication failure volume`, while the second detects a potentially suspicious `sequence of authentication behavior`.

For the report, I kept the second query as the primary example and treated the first as the introductory baseline. 
It better supports the principle that useful detection should focus on behavior and context, not only on isolated log values.



## 8. RBAC Policy Violations

RBAC violation detection determines whether a user performed a `esource-management action` that falls outside their expected authorization.

Unlike simply detecting an administrative action, this detection requires an `expected-access baseline`. 
The baseline `defines which identities are authorized to perform privileged operations`.

In this example, the approved administrators are defined first. `AzureActivity` is then examined for successful write or delete operations performed by identities outside that approved group.

```kql
let ApprovedAdmins = dynamic([
    "alice@contoso.com",
    "securityadmin@contoso.com"
]);
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatusValue =~ "Success"
| where OperationNameValue has_any (
    "write",
    "delete"
)
| where Caller !in~ (ApprovedAdmins)
| project
    TimeGenerated,
    Caller,
    OperationNameValue,
    ResourceGroup,
    SubscriptionId,
    ActivityStatusValue
| order by TimeGenerated desc
```

`AzureActivit`y provides information about `Azure resource-management operations`, including the `identity responsible for an action`. 
This allows observed activity to be compared against an established authorization baseline.

The detection logic is:

```kql
Observed Action → Identify Caller → Compare Against Expected Authorization → Flag Unexpected Activity
```

- An important distinction is that the query does not prove that every non-approved action is malicious. 
- It identifies activity that does not match the expected authorization model and therefore requires investigation.


# IAM Detection Coverage

The eight detection examples demonstrate how different IAM security conditions can be identified using Microsoft Sentinel telemetry.

|---------------|-------------------|---------------------|
|IAM Detection	|Primary KQL Source	|Detection Objective|
|---------------|-------------------|---------------------|
|Excessive privileges	|AuditLogs	|Identify potentially excessive role assignments|
|Unauthorized administrative access	|AuditLogs	|Identify sensitive actions performed by unexpected actors|
|Repeated failed authentication	|SigninLogs	|Detect repeated authentication failures|
|Dormant account activity	|SigninLogs	|Detect renewed activity from previously inactive identities|
|Privilege escalation	|AuditLogs	|Identify unexpected privileged-role assignments|
|Disabled-account authentication	|AuditLogs + SigninLogs	|Detect authentication occurring after an account was disabled|
|MFA fatigue	|SigninLogs	|Detect repeated MFA failures followed by successful authentication|
|RBAC policy violation	|AzureActivity + authorization baseline	|Identify resource actions inconsistent with expected authorization|


# Demonstrating Detection Flexibility
These detections also demonstrate that the security concept is independent of the implementation technology.

The methodology remains consistent:
```kql
	IAM Principle → Security Behavior → Detection Logic → Evidence → Investigation
```

The same detection logic can then be implemented using different technologies:
- Python can evaluate identity and authorization data programmatically
- Microsoft Sentinel/KQL can analyze enterprise telemetry for evidence of the same security condition.

For example:
<p align="center">
<img width="433" height="588" alt="understanding of the underlying IAM security condition" src="https://github.com/user-attachments/assets/e768a0d0-c373-4b11-bb42-7d8f99ffb920" />
</p>

This approach demonstrates an understanding of the underlying IAM security condition, rather than dependence on a particular programming language or security platform.

One small but important improvement I made: I removed the implication that the `ApprovedAdmins` query is a complete RBAC validation system. It is really a simplified authorization baseline for the lab. Later, our more advanced version can compare actual entitlements, roles, resources, PIM eligibility, and other authorization data rather than relying on a hard-coded administrator list.
That keeps the report technically accurate while still making the example easy to understand.


# Lessons Learned

The IAM implementation demonstrated that effective identity security extends beyond authentication and account administration. Identity activity must be evaluated against expected roles, privileges, access policies, and organizational requirements to determine whether an observed action is authorized.

## Several key lessons emerged:

- Identity does not equal authorization. Successfully authenticating an identity establishes who the user is but does not determine what that identity should be permitted to access.
- Privilege alone is not evidence of compromise. Administrative activity must be compared against expected roles, approved privileges, PIM/PAM controls, and business requirements.
- Authorization requires a baseline. Detecting an RBAC violation requires knowledge of expected access. Without an entitlement baseline, telemetry may show what occurred but cannot always determine whether the action was authorized.
-Behavior provides stronger detection context than isolated events. For example, repeated MFA failures followed by successful authentication provide greater investigative value than simply counting MFA failures.
- Detection logic is portable. The same IAM security condition can be represented programmatically in Python or investigated through Microsoft Sentinel using KQL.
- Telemetry and identity state serve different purposes. Microsoft Entra and related identity services maintain identity and authorization state, while Sentinel/KQL provides visibility into recorded activity. Correlating these sources produces stronger security decisions.
- Continuous governance is necessary. Roles and entitlements that are appropriate today may become excessive as users change responsibilities, projects end, contractors leave, or systems evolve.

The primary lesson is that effective IAM detection asks not simply “What happened?”, but:
```bash
	"Was this identity authorized to perform this action, on this resource, under these conditions?"
```

# Conclusion

Identity and Access Management provides a foundational security layer for controlling how users, administrators, service identities, and external identities interact with enterprise resources.

This implementation applied IAM principles across authentication, authorization, least privilege, RBAC, privileged access, governance, monitoring, and detection. Python demonstrated how IAM security conditions can be evaluated programmatically, while Microsoft Sentinel and KQL demonstrated how similar logic can be applied to enterprise telemetry.

The detections developed for excessive privileges, unauthorized administrative access, repeated authentication failures, dormant account activity, privilege escalation, disabled-account authentication, MFA fatigue, and RBAC violations demonstrate a progression from basic event monitoring toward behavioral and authorization-aware detection.

The resulting security model can be summarized as:

```bash
Identity → Authenticate → Authorize → Control Privilege → Govern → Detect → Investigate → Respond
```

The objective of IAM is therefore not simply to determine whether a user can sign in. It is to continuously ensure that the right identity has the right access to the right resource under the right conditions—and that deviations can be detected and investigated.


# Framework Alignment

Framework / Standard	How This IAM Project Aligns
NIST Cybersecurity Framework (CSF) 2.0	Identity management, authentication, access control, monitoring, detection, and response support the Protect, Detect, Respond, and Govern functions.
NIST SP 800-53	Maps strongly to Access Control (AC), Identification and Authentication (IA), Audit and Accountability (AU), and related security-control families.
NIST SP 800-63 Digital Identity Guidelines	Provides guidance around digital identity, authentication, authenticator management, federation, and assurance.
Zero Trust Architecture — NIST SP 800-207	Supports explicit verification, least privilege, contextual access decisions, and continuous evaluation rather than implicit trust.
CIS Controls v8	Aligns particularly with Account Management, Access Control Management, Audit Log Management, and monitoring of security-relevant account activity.
MITRE ATT&CK	Provides adversary-behavior mappings for techniques involving valid accounts, account manipulation, additional cloud roles, MFA abuse, and other identity-focused activity.

There is also a useful way to position these rather than presenting them as six equivalent “frameworks”:

- Governance & Security Framework: NIST CSF 2.0
- Security Controls: NIST SP 800-53 / CIS Controls
- Digital Identity: NIST SP 800-63
- Architecture: NIST Zero Trust / SP 800-207
- Threat Behavior: MITRE ATT&CK

That classification would look very professional in the report because it shows you understand what each framework is actually contributing, rather than putting a collection of framework logos at the bottom of an IAM project.

For this particular project, I would make NIST CSF 2.0 the umbrella, with NIST 800-53 + 800-63 + Zero Trust underneath it, and use MITRE ATT&CK only when mapping the detection scenarios to adversary behavior.





