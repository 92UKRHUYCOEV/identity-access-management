# Identity Access Management (IAM)

<p align="center">
<img width="3258" height="1086" alt="image" src="https://github.com/user-attachments/assets/46176870-84b1-492b-a73d-b6b1bf991bd9" />
</p>

## Project Flow:
	```python
		Identity → Authentication → Authorization → Privileged Access → Monitoring → Detection → Response → Automate
	```

# IAM Implementation Context

Identity and Access Management (IAM) controls how identities authenticate, what resources they can access, how privileges are governed, and how identity activity is monitored.
This project approaches IAM from a security-engineering and detection perspective, using least privilege, MFA, RBAC, Conditional Access, privileged-access management, and identity lifecycle governance as the security foundation.

## Core Principle
```yaml
Identity does not equal authorization.
```
	
Successful authentication establishes identity, but does not establish that every subsequent action is authorized. Activity must be evaluated against expected roles, privileges, resources, and access policies.

Detection Methodology
IAM Principle
↓
Expected Behavior
↓
Observed Telemetry
↓
Detection Logic
↓
Evidence
↓
Investigation
	```yaml
	Behavior provides stronger detection context than isolated events.
	```
Python demonstrates the detection logic programmatically, while Microsoft Sentinel and KQL apply that logic to enterprise identity telemetry.

The central investigative question is:
	```yaml
	Was this identity authorized to perform this action, on this resource, under these conditions?
	```


## IAM Implementation Lifecycle
```Python
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
    if len(roles) >= 3:
        print(f"[ALERT] {user} may have excessive privileges: {roles}")
```

```yaml
Detection Logic
Identify User
↓
Count Assigned Roles
↓
Threshold Exceeded
↓
Review for Excessive Privilege
```
The threshold is an example. In production, privileges should be compared against the user’s expected role.


## 2. Detect Unauthorized Administrative Access

``` Python
authorized_admins = ["alice", "security_admin"]

admin_events = [
    {"user": "alice", "action": "add_member_to_role"},
    {"user": "bob", "action": "read_reports"},
    {"user": "charlie", "action": "reset_user_password"}
]

privileged_actions = [
    "add_member_to_role",
    "remove_member_from_role",
    "reset_user_password",
    "delete_user",
    "add_service_principal"
]

for event in admin_events:
    if (
        event["action"] in privileged_actions
        and event["user"] not in authorized_admins
    ):
        print(
            f"[ALERT] Unauthorized administrative action: "
            f"{event['user']} performed {event['action']}"
        )
```

```yaml
Detection Logic
Sensitive Administrative Action
↓
Identify Actor
↓
Compare Against Approved Administrators
↓
Unauthorized Actor Detected
↓
Investigate
```
This now matches the KQL concept better: we're detecting a sensitive administrative action by an unauthorized actor, rather than merely checking whether someone has an admin role.


## 3. Detect Repeated Failed Logins

``` Python
To match the revised KQL, the Python example should also count distinct authentication flows, rather than simply counting every event.
login_events = [
    {"user": "alice", "status": "failed", "correlation_id": "A101"},
    {"user": "alice", "status": "failed", "correlation_id": "A101"},
    {"user": "alice", "status": "failed", "correlation_id": "A102"},
    {"user": "alice", "status": "failed", "correlation_id": "A103"},
    {"user": "bob", "status": "success", "correlation_id": "B101"}
]

failed_logins = {}

for event in login_events:
    if event["status"] == "failed":
        user = event["user"]
        failed_logins.setdefault(user, set())
        failed_logins[user].add(event["correlation_id"])

for user, correlation_ids in failed_logins.items():
    failure_count = len(correlation_ids)

    if failure_count >= 3:
        print(
            f"[ALERT] Multiple failed authentication flows: "
            f"{user} ({failure_count} failures)"
        )
```

```yaml
Detection Logic
Failed Authentication
↓
Identify Distinct Authentication Flow
↓
Count Failures by User
↓
Threshold Exceeded
↓
Investigate
```
This mirrors the KQL use of dcount(CorrelationId) and prevents duplicate records from inflating the failure count.


## 4. Detect Dormant Account Usage
To match the KQL, the Python example should detect a previously inactive identity becoming active, not simply identify an account that has been dormant.

``` Python
from datetime import datetime, timedelta
historical_logins = {
    "alice": datetime.now() - timedelta(days=5),
    "bob": datetime.now() - timedelta(days=120)
}
recent_logins = {
    "bob": datetime.now()
}
dormant_threshold = 90
for user, current_login in recent_logins.items():
    previous_login = historical_logins.get(user)
if previous_login:
        days_inactive = (current_login - previous_login).days
if days_inactive >= dormant_threshold:
            print(
                f"[ALERT] Dormant account reactivated: "
                f"{user} after {days_inactive} days"
            )
```

```yaml
Detection Logic
Previously Inactive Identity
↓
Successful Login Detected
↓
90+ Days Since Previous Login
↓
Dormant Account Reactivated
↓
Investigate
```
This now mirrors the KQL logic much better: it detects activity from a dormant account, not just dormancy itself.


## 5. Detect Privilege Escalation
```Python
from datetime import datetime
approved_admins = ["security_admin", "iam_admin"]
privileged_roles = [
    "global_admin",
    "privileged_role_admin",
    "security_admin",
    "user_admin"
]
role_changes = [
    {
        "actor": "security_admin",
        "user": "alice",
        "new_role": "global_admin",
        "via_pim": True,
        "hour": 10
    },
    {
        "actor": "unknown_admin",
        "user": "bob",
        "new_role": "global_admin",
        "via_pim": False,
        "hour": 22
    }
]
for change in role_changes:
    if change["new_role"] in privileged_roles:
unexpected_actor = change["actor"] not in approved_admins
        outside_change_window = change["hour"] < 8 or change["hour"] > 18
        outside_pim = not change["via_pim"]
if outside_pim and (
            unexpected_actor or outside_change_window
        ):
            print(
                f"[ALERT] Unexpected privileged role assignment: "
                f"{change['user']} received {change['new_role']} "
                f"from {change['actor']}"
            )
```

```yaml
Detection Logic
Privileged Role Assignment
↓
Exclude Expected PIM Activity
↓
Evaluate Actor and Timing
↓
Unexpected Privileged Assignment
↓
Investigate
````
This now aligns with the updated KQL logic instead of treating every privileged-role assignment as malicious.


## 6. Detect Disabled Account Authentication
``` Python
from datetime import datetime, timedelta
account_events = [
    {
        "user": "bob",
        "event": "disabled",
        "time": datetime.now() - timedelta(hours=2)
    }
]
login_events = [
    {
        "user": "bob",
        "status": "success",
        "time": datetime.now() - timedelta(hours=1)
    }
]
disabled_accounts = {}
for event in account_events:
    if event["event"] == "disabled":
        disabled_accounts[event["user"]] = event["time"]
for event in login_events:
    user = event["user"]
if (
        event["status"] == "success"
        and user in disabled_accounts
        and event["time"] > disabled_accounts[user]
    ):
        print(
            f"[CRITICAL] Successful authentication after account disablement: "
            f"{user}"
        )
```
```yaml
Detection Logic
Account Disabled
↓
Later Successful Login Detected
↓
Compare Event Times
↓
Authentication Occurred After Disablement
↓
Investigate Immediately
```
This now mirrors the stronger KQL correlation instead of only checking whether an account is currently marked disabled.


## 7. Detect MFA Fatigue Behavior
To match the revised KQL, the Python example should count distinct MFA rejection flows and then look for a later successful authentication.

```kql
mfa_events = [
    {"user": "alice", "result": "denied", "correlation_id": "A101"},
    {"user": "alice", "result": "denied", "correlation_id": "A101"},
    {"user": "alice", "result": "denied", "correlation_id": "A102"},
    {"user": "alice", "result": "denied", "correlation_id": "A103"},
    {"user": "alice", "result": "approved", "correlation_id": "A104"}
]
mfa_denials = {}
for event in mfa_events:
    user = event["user"]
if event["result"] == "denied":
        mfa_denials.setdefault(user, set())
        mfa_denials[user].add(event["correlation_id"])
if (
        event["result"] == "approved"
        and len(mfa_denials.get(user, set())) >= 3
    ):
        print(
            f"[ALERT] Possible MFA fatigue pattern: "
            f"{user} authenticated after "
            f"{len(mfa_denials[user])} distinct MFA rejections"
        )
```
```yaml
Detection Logic
MFA Challenge Rejected
↓
Count Distinct Authentication Flows
↓
Multiple Rejections for Same Identity
↓
Successful Authentication Follows
↓
Investigate
```
This now mirrors the KQL logic by avoiding duplicate counting and focusing on the rejection → success behavioral sequence.


## 8. Detect Access Outside Normal Role Permissions
To match the revised KQL, the Python example should focus on sensitive operations and compare the actor against an approved authorization baseline.

```kql
approved_admins = [
    "alice",
    "security_admin"
]

sensitive_actions = [
    "role_assignment_write",
    "role_assignment_delete",
    "network_security_group_write",
    "network_security_group_delete",
    "virtual_machine_delete"
]

activity_log = [
    {"user": "alice", "action": "role_assignment_write"},
    {"user": "bob", "action": "read_reports"},
    {"user": "charlie", "action": "virtual_machine_delete"}
]

for event in activity_log:
    user = event["user"]
    action = event["action"]

    if (
        action in sensitive_actions
        and user not in approved_admins
    ):
        print(
            f"[ALERT] Unauthorized sensitive action: "
            f"{user} performed {action}"
        )
```

```yaml
Detection Logic
Sensitive Operation
↓
Identify Actor
↓
Compare Against Authorization Baseline
↓
Unexpected Actor Detected
↓
Investigate
```
This now aligns with the revised RBAC KQL by focusing on specific sensitive actions, rather than treating all activity outside a role as equally important.


## 9. Detect OAuth / Illicit Consent Grant Abuse
This matches the KQL concept for OAuth / Illicit Consent Grant Abuse — T1528.

```kql
high_risk_permissions = [
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All"
]

consent_events = [
    {
        "user": "alice",
        "application": "ReportViewer",
        "permissions": ["Mail.Read"]
    },
    {
        "user": "bob",
        "application": "UnknownApp",
        "permissions": ["Mail.ReadWrite", "Files.ReadWrite.All"]
    }
]

for event in consent_events:
    risky_permissions = [
        permission
        for permission in event["permissions"]
        if permission in high_risk_permissions
    ]

    if risky_permissions:
        print(
            f"[ALERT] High-risk application consent: "
            f"{event['user']} granted {risky_permissions} "
            f"to {event['application']}"
        )
```
```yaml
Detection Logic
Application Consent Granted
↓
Identify User and Application
↓
Inspect Granted Permissions
↓
High-Risk Permission Detected
↓
Investigate
```

## 10. Detect Service Principal Credential Abuse
This matches the KQL concept for Service Principal Credential Abuse — T1098.001.

```kql
approved_admins = [
    "security_admin",
    "iam_admin"
]

credential_events = [
    {
        "actor": "security_admin",
        "service_principal": "BackupAutomation",
        "credential_type": "certificate"
    },
    {
        "actor": "unknown_admin",
        "service_principal": "FinanceApp",
        "credential_type": "client_secret"
    }
]

for event in credential_events:
    if event["actor"] not in approved_admins:
        print(
            f"[ALERT] Unexpected service principal credential change: "
            f"{event['actor']} added a {event['credential_type']} "
            f"to {event['service_principal']}"
        )
```

```yaml
Detection Logic
Service Principal Credential Added
↓
Identify Actor
↓
Compare Against Approved Administrators
↓
Unexpected Credential Change
↓
Investigate for Persistence
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
	8. detect_rbac_policy_violations.py
	9. detect_oauth_illicit_grant_abuse.py
   10. detect_service_credential_abuse.py
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

## 1. Excessive Privileges
This looks for users receiving an unusually high number of role assignments.
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
Unauthorized administrative access detection identifies sensitive administrative actions performed by identities outside the approved administrator baseline.

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

```yaml
Detection Logic
Sensitive Administrative Action
↓
Identify Actor
↓
Compare Against Approved Administrators
↓
Unauthorized Actor Detected
↓
Investigate
```

The detection flags privileged actions performed by identities outside the approved administrative baseline.


## 3. Repeated Failed Authentication
Repeated failed-authentication detection identifies identities with multiple distinct failed authentication flows within a short time period.

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize
    FailedAttempts = dcount(CorrelationId),
    Applications = make_set(AppDisplayName),
    SourceIPs = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

```yaml
Detection Logic
Failed Authentication
↓
Count Distinct Authentication Flows (CorrelationId)
↓
Five or More Failures Within 10 Minutes
↓
Threshold Exceeded
↓
Investigate
```
Using CorrelationId reduces double counting when multiple SigninLogs records belong to the same authentication flow. 


## 4. Dormant Account Activity
Dormant-account detection identifies identities that become active after an extended period of inactivity.

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

```yaml
Detection Logic
Previously Inactive Identity
↓
Successful Sign-In Detected
↓
90+ Days Since Previous Login
↓
Dormant Account Reactivated
↓
Investigate
```
The usable lookback depends on the retention period available in SigninLogs.


## 5. Privilege Escalation
Privilege escalation detection identifies unexpected assignments of privileged roles. Higher-risk conditions include assignments made outside PIM, by unexpected administrators, or outside approved change windows.

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
| extend Identity =
    tostring(InitiatedBy.app.displayName)
| extend TargetUser =
    tostring(TargetResources[0].userPrincipalName)
| extend RoleName =
    tostring(TargetResources[0].displayName)
| where RoleName in~ (PrivilegedRoles)
| where Identity != "MS-PIM"
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
    Identity,
    TargetUser,
    RoleName,
    ApprovedAdministrator,
    OutsideChangeWindow,
    OperationName,
    Result
| order by TimeGenerated desc
```

```yaml
Detection Logic
Privileged Role Assignment
↓
Exclude Expected PIM Activity
↓
Evaluate Actor and Timing
↓
Unexpected Privileged Assignment
↓
Investigate
```
A privileged-role assignment does not automatically indicate malicious activity. Direct or unexpected assignments outside normal PIM and administrative workflows warrant greater scrutiny.


## 6. Disabled-Account Authentication
Disabled-account detection can be approached at two levels.

Baseline Detection
ResultType == 50057 in SigninLogs identifies sign-in attempts involving a disabled account.
Question: Did a disabled account attempt to authenticate?

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 50057
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    Location,
    ResultDescription
| order by TimeGenerated desc
```

Advanced Detection
A stronger detection correlates the account-disable event in AuditLogs with a later successful authentication in SigninLogs.

```kql
let DisabledAccounts =
    AuditLogs
    | where TimeGenerated > ago(30d)
    | where OperationName == "Update user"
    | mv-expand Property = TargetResources[0].modifiedProperties
    | extend
        PropertyName = tostring(Property.displayName),
        NewValue = tostring(Property.newValue),
        DisabledUser = tostring(TargetResources[0].userPrincipalName)
    | where PropertyName == "AccountEnabled"
    | where NewValue contains "false"
    | summarize DisabledTime = max(TimeGenerated) by DisabledUser;
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

Question: Did the identity successfully authenticate after the account was disabled?

## Detection Progression
```yanl
Disabled Account Attempt (50057)
↓
Baseline Detection
↓
Account Disable Event Confirmed
↓
Later Successful Authentication
↓
Higher-Risk Condition
↓
Investigate
```


## 7. MFA Fatigue
MFA fatigue detection looks for repeated multi-factor authentication challenges that may indicate an attacker is attempting to pressure a user into approving an unauthorized sign-in. A simple count of MFA-related failures can create false positives because not every MFA failure represents a user explicitly rejecting an authentication request. For higher-fidelity detection, the query should distinguish user-declined MFA challenges from other authentication conditions.

Microsoft Entra SigninLogs can record ResultType == 500121 when authentication fails during a strong authentication request. The Status information can then be used to identify cases in which the user specifically declined the MFA request.

An additional consideration is CorrelationId. A single authentication flow may generate multiple SigninLogs records sharing the same CorrelationId.  Counting raw records can therefore inflate the apparent number of MFA attempts.  Grouping or deduplicating by CorrelationId better represents distinct authentication flows. 

### MFA Rejection Baseline

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 500121
| where tostring(Status) has "MFA denied; user declined the authentication"
| summarize
    MFARejections = dcount(CorrelationId),
    SourceIPs = make_set(IPAddress),
    Applications = make_set(AppDisplayName)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where MFARejections >= 3
| order by MFARejections desc
```

The important change is:
```yaml
	Raw failure records → Distinct authentication flows
```
rather than assuming:
```yaml
	One SigninLogs row = one MFA attempt
```

This baseline identifies an identity experiencing multiple distinct user-declined MFA authentication flows during a short period.

However, repeated MFA rejection still does not prove MFA fatigue. 

A user could legitimately reject authentication attempts that they did not initiate. 

The more meaningful security condition remains the behavioral sequence already established in the original project:
```yaml
	Repeated MFA Rejections → Same Identity → Later Successful Authentication → Investigation
```

Primary Behavioral Detection
```KQL
let MFAFailures =
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 500121
    | where tostring(Status) has "MFA denied; user declined the authentication"
    | summarize
        FailureCount = dcount(CorrelationId),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by UserPrincipalName
    | where FailureCount >= 3;

let SuccessfulSignins =
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 0
    | summarize arg_max(TimeGenerated, *)
        by UserPrincipalName, CorrelationId
    | project
        UserPrincipalName,
        SuccessfulLogin = TimeGenerated,
        CorrelationId,
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
    AppDisplayName,
    CorrelationId
| order by SuccessfulLogin desc
```

```yaml
Detection Logic
MFA challenge rejected
↓
Count distinct authentication flows (CorrelationId)
↓
Multiple rejections for same identity
↓
Successful authentication follows
↓
Higher-risk behavioral sequence
↓
Investigate
```

This still does not automatically establish compromise. The sequence should be investigated using source IP, device information, application access, geographic location, Conditional Access results, authentication details, and user confirmation.


## 8. RBAC Policy Violations

RBAC violation detection identifies sensitive Azure resource actions performed by identities outside their expected authorization.
To reduce noise, the detection focuses on specific security-sensitive operations rather than all Azure write and delete activity. This addresses Mohammed's concern that the original filter was too broad for production. 

```kQL
let ApprovedAdmins = dynamic([
    "alice@contoso.com",
    "securityadmin@contoso.com"
]);

let SensitiveOperations = dynamic([
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleAssignments/delete",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/delete",
    "Microsoft.Compute/virtualMachines/delete"
]);

AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatusValue =~ "Success"
| where OperationNameValue in~ (SensitiveOperations)
| where Caller !in~ (ApprovedAdmins)
| project
    TimeGenerated,
    Caller,
    OperationNameValue,
    ResourceGroup,
    ResourceId,
    SubscriptionId,
    ActivityStatusValue
| order by TimeGenerated desc
```
```YAML
Detection Logic
Sensitive Azure Operation
↓
Identify Caller
↓
Compare Against Authorization Baseline
↓
Unexpected Actor
↓
Investigate
```

The detection does not establish malicious activity. It identifies sensitive operations that do not match the expected authorization model and require investigation.

## 9. OAuth / Illicit Consent Grant Abuse — T1528

OAuth consent abuse occurs when a user authorizes a malicious application to access organizational resources. This can bypass the need to defeat MFA because access is granted through application permissions.
This detection monitors AuditLogs for application consent involving high-risk permissions such as Mail.ReadWrite, Files.ReadWrite.All, and Directory.ReadWrite.All. 
Example Detection

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any (
    "Consent to application",
    "Add delegated permission grant"
)
| extend Actor =
    tostring(InitiatedBy.user.userPrincipalName)
| extend TargetApplication =
    tostring(TargetResources[0].displayName)
| extend ModifiedProperties =
    tostring(TargetResources[0].modifiedProperties)
| where ModifiedProperties has_any (
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All"
)
| project
    TimeGenerated,
    Actor,
    TargetApplication,
    OperationName,
    ModifiedProperties,
    Result
| order by TimeGenerated desc
```

```yaml
Detection Logic
Application Consent Granted
↓
Identify User and Application
↓
Inspect Granted Permissions
↓
High-Risk Permission Detected
↓
Investigate
```

The detection identifies application consent involving sensitive permissions that should be validated against expected business requirements.


## 10. Service Principal Credential Abuse — T1098.001
Service principals are non-human identities used by applications, automation, and cloud services. An attacker with sufficient privileges may add a secret or certificate to an existing service principal, creating a potential persistence mechanism.

This detection monitors AuditLogs for credential and secret changes involving service principals. 
Example Detection

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any (
    "Add service principal credentials",
    "Update application",
    "Certificates and secrets management"
)
| extend Actor =
    tostring(InitiatedBy.user.userPrincipalName)
| extend TargetServicePrincipal =
    tostring(TargetResources[0].displayName)
| extend TargetId =
    tostring(TargetResources[0].id)
| project
    TimeGenerated,
    Actor,
    TargetServicePrincipal,
    TargetId,
    OperationName,
    TargetResources,
    Result
| order by TimeGenerated desc
```

```yaml
Detection Logic
Service Principal Modified
↓
Credential or Secret Added
↓
Identify Actor
↓
Compare Against Expected Workflow
↓
Unexpected Credential Change
↓
Investigate for Persistence
```

This extends IAM detection beyond human users to application and service identities.

# IAM Detection Coverage
The eight detection examples demonstrate how different IAM security conditions can be identified using Microsoft Sentinel telemetry.

| # |IAM Detection	|Primary KQL Source	|Detection Objective|
|---|---------------|-------------------|---------------------|
| 1 |Excessive privileges	|AuditLogs	|Identify potentially excessive role assignments|
| 2 |Unauthorized administrative access	|AuditLogs	|Identify sensitive actions performed by unexpected actors|
| 3 |Repeated failed authentication	|SigninLogs	|Detect repeated authentication failures|
| 4 |Dormant account activity	|SigninLogs	|Detect renewed activity from previously inactive identities|
| 5 |Privilege escalation	|AuditLogs	|Identify unexpected privileged-role assignments|
| 6 |Disabled-account authentication	|AuditLogs + SigninLogs	|Detect authentication occurring after an account was disabled|
| 7 |MFA fatigue	|SigninLogs	|Detect repeated MFA failures followed by successful authentication|
| 8 |RBAC policy violation	|AzureActivity + authorization baseline	|Identify resource actions inconsistent with expected authorization|
| 9 |OAuth / Illicit Consent Grant Abuse |AuditLogs |Identify high-risk application consent grants   |
| 10 |Service Principal Credential Abuse  |AuditLogs |Identify unexpected credential additions to service principals |


# Demonstrating Detection Flexibility
These detections also demonstrate that the security concept is independent of the implementation technology.

The methodology remains consistent:
```bash
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

|Framework / Standard	|How This IAM Project Aligns |
|-----------------------|----------------------------|
|NIST Cybersecurity Framework (CSF) 2.0	|Identity management, authentication, access control, monitoring, detection, and response support the Protect, Detect, Respond, and Govern functions. |
|NIST SP 800-53	|Maps strongly to Access Control (AC), Identification and Authentication (IA), Audit and Accountability (AU), and related security-control families. |
|NIST SP 800-63 Digital Identity Guidelines	|Provides guidance around digital identity, authentication, authenticator management, federation, and assurance. |
|Zero Trust Architecture — NIST SP 800-207	|Supports explicit verification, least privilege, contextual access decisions, and continuous evaluation rather than implicit trust. |
|CIS Controls v8	|Aligns particularly with Account Management, Access Control Management, Audit Log Management, and monitoring of security-relevant account activity. |
|MITRE ATT&CK	|Provides adversary-behavior mappings for techniques involving valid accounts, account manipulation, additional cloud roles, MFA abuse, and other identity-focused activity. |

There is also a useful way to position these rather than presenting them as six equivalent “frameworks”:

- Governance & Security Framework: NIST CSF 2.0
- Security Controls: NIST SP 800-53 / CIS Controls
- Digital Identity: NIST SP 800-63
- Architecture: NIST Zero Trust / SP 800-207
- Threat Behavior: MITRE ATT&CK

For this particular project, I would make NIST CSF 2.0 the umbrella, with NIST 800-53 + 800-63 + Zero Trust underneath it, and use MITRE ATT&CK only when mapping the detection scenarios to adversary behavior.





