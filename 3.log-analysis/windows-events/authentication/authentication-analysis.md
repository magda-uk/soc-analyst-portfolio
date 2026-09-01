# Authentication Log Analysis (T1110 / T1078)

## Relevant Event Types
- SigninLogs
- AADNonInteractiveUserSignInLogs
- AADServicePrincipalSignInLogs

## Key Fields to Review
- Timestamp
- UserPrincipalName
- IPAddress
- ResultType
- FailureReason
- DeviceDetail
- Location
- MFARequired / MFAResult

## Common Benign Patterns
- User mistyping password
- VPN reconnects causing location jumps
- MFA failures due to expired tokens
- Login attempts from known corporate IP ranges

## Common Malicious Patterns
- Password spraying (many users, same IP)
- Brute-force (many failures, same user)
- Impossible travel (two distant locations within minutes)
- MFA fatigue (multiple MFA prompts)
- Sign-ins from TOR/VPN/proxy networks

## Example Raw Events
(Insert JSON or raw log snippets from Sentinel)

## Useful KQL Queries
```kql
SigninLogs
| where ResultType != 0
| project Timestamp, UserPrincipalName, IPAddress, ResultType, FailureReason
| order by Timestamp desc
```
```kql
SigninLogs
| where Location != PreviousLocation
| project Timestamp, UserPrincipalName, IPAddress, Location
```
```kql
AADNonInteractiveUserSignInLogs
| where ResultType != 0
| project Timestamp, UserPrincipalName, AppDisplayName, IPAddress
```

