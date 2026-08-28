# KQL Testing Checklist for SOC Analysts

This checklist ensures that advanced KQL queries (anomalies, hunting, detections) run correctly, return meaningful results, and do not produce errors in Sentinel or Log Analytics.


## 1. Validate the Dataset
- Run a simple query first:
```kql
SigninLogs | take 10
```
- Confirm the table exists.

- Confirm you have permissions.

- Confirm data is flowing.

## 2. Validate Fields
```kql
SigninLogs | getschema
```
-  Confirm fields used in the query exist:

        Location

        FailureReason

        PreviousLocation

        ScriptBlockText

        GrantedAccess

- Remove or replace fields that do not exist in your tenant.

## 3. Test each block separately
```kql
ImpossibleTravel
```
```kql
MfaFatigue
```
```kql
SuspiciousIPs
```
- Each block must return results or at least compile.

- Fix errors before combining blocks.
## 4. Limit Results During Testing
Avoid heavy queries:

```kql
| limit 50
```
This prevents:

    timeouts

    slow queries

    unnecessary cost

## 5. Use project to Reduce Noise
Example:

```kql
| project Timestamp, UserPrincipalName, IPAddress, Location
```
This helps validate logic without overwhelming output.

## 6. Test with Realistic Filters
Use real users, IPs, or time ranges:

```kql
| where UserPrincipalName == "marta@company.com"
| where Timestamp > ago(7d)
```
This ensures the query behaves correctly with real data.

## 7. Validate Logic with extend
Example:

```kql
| extend TimeDiff = datetime_diff('minute', PreviousTimestamp, Timestamp)
```
Check if the logic produces expected values.

## 8. Check Performance
    
    Avoid unnecessary join operations.

    Avoid scanning entire tables without filters.

    Use where Timestamp > ago(7d) when possible.
    

## 9. Final Full Run
Once validated:

    Remove limit

    Remove debug project

    Run the full query

    Save it in the correct folder (triage, anomalies, hunting)

## 10. Commit Guidelines
Use clear commit messages:

```Code
Add advanced authentication anomaly hunting query
Refactor KQL structure for clarity
Add KQL testing checklist for analysts
```
