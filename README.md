# Identity Access Management (IAM)

<img width="3258" height="1086" alt="image" src="https://github.com/user-attachments/assets/46176870-84b1-492b-a73d-b6b1bf991bd9" />

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
	
```python
PYTHON DETECTION SCRIPTS
```
1. Detect Excessive Privileges
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

2. Detect Unauthorized Administrative Access
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

3. Detect Repeated Failed Logins
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

4. Detect Dormant Account Usage
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

5. Detect Privilege Escalation
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

6. Detect Disabled Account Authentication
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

7. Detect MFA Fatigue Behavior
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

8. Detect Access Outside Normal Role Permissions
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


