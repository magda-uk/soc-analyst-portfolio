# Security Event Analysis: Entra ID Sign-in Logs (Cloud Telemetry)

## 🟪 Summary
This analysis expands the scope from on-premises endpoint telemetry (such as Event ID 4672) to cloud-based identity monitoring within Microsoft Entra ID (formerly Azure AD). Monitoring sign-in activity and application access is crucial for detecting unauthorised access, compromised credentials, or anomalous behaviour within the cloud infrastructure. 

## 🟪 Case Study: Cloud Identity Sign-ins (Account: John Smith)

![KQL Query Results: Entra ID Sign-ins](/3.log-analysis/entra-id/images/azure.png)

A KQL (Kusto Query Language) query was executed in Azure Log Analytics to review recent authentication activity. The results highlight standard user behaviour:

* **User**: John Smith (Logistics)
* **Target Applications**: "My Profile" and "My Signins"
* **Activity**: The user is accessing self-service identity management portals, likely to review their own security information or update profile details.

While this specific activity is benign, maintaining visibility into sign-in logs allows SOC analysts to establish a baseline for normal user behaviour. In a production environment, this data is typically queried directly from the `SigninLogs` table. Deviations—such as sign-ins from impossible travel locations, unfamiliar IP addresses, or unexpected access to administrative portals—would trigger immediate investigation.

## 🟪 Security Recommendations & Conclusion
To ensure comprehensive visibility across a hybrid environment, cloud identity logs must be actively correlated with endpoint activity:

* **Entra ID `SigninLogs`**: Monitor for conditional access failures, legacy authentication attempts, and access from unmanaged devices.
* **Entra ID `AuditLogs`**: Track changes to role assignments. Privileged Identity Management (PIM) activations in the cloud act as the direct counterpart to local privileged logons (Event ID 4672).
* **Cross-Environment Correlation**: A suspicious cloud sign-in followed by unexpected privileged activity on a local endpoint represents a high-confidence indicator of compromise (IoC) and lateral movement.

By bridging endpoint events with cloud telemetry, defenders can effectively track threat actors across the entire kill chain, ensuring no blind spots remain between on-premises and cloud identities.

## 🪪 Author

**Magda Dominguez**  
*SOC Analyst (L1-ready) Bristol, UK*  
Focused on Blue Team operations, detection engineering and log analysis.