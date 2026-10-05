# Known standards conflicts and decisions

This register records conflicts affecting the CSC and ETSI remote signing implementation. 

| Issue | Requirement A | Requirement B | Status | Decision |
| --- | --- | --- | --- | --- |
| SD-JWT `qesApproval` hash input | ETSI TS 119 432 V1.3.1, B.6.3 requires hashing the UTF-8 JSON bytes. <br/>`base64(hash(original UTF 8 qesApprovalRequest))` | CSC Data Model Bindings 1.0.0, 7.2.1.2 (SD-JWT VC-based encoding) requires hashing the base64url representation of the UTF-8 JSON. <br/>`base64(hash(base64Url(Original UTF 8 qesApprovalRequest)))` | **Pending mediation.** The current SD-JWT path follows the CSC definition; the mdoc path hashes decoded JSON. | No decision yet. Hashing the original decoded UTF-8 JSON bytes for both formats is a proposed resolution only. Obtain the user's decision before changing hash behavior or corresponding tests. |
| Document reference checksum representation | ETSI TS 119 432 V1.3.1, A.6.4 specifies the structured Hash object from CSC Data Model 1.0.0, 7.4. | CSC Data Model Bindings 1.0.0 checksum requirements specify SRI syntax. | **Approved.** Previously mediated by the user. | Use structured Hash throughout the active project paths. Retain `ChecksumSerializer` as an unused object with `@Suppress("unused")` and explanatory KDoc. Do not add active SRI compatibility. This approval covers document reference checksum representation only. |

## Section for Agents
Requirements above refer to the local editions listed in the [implementation plan](csc_2.2.0.0/IMPLEMENTATION_PLAN.md).
Pending decisions do not authorize implementation of a proposed resolution. Approved decisions apply only
within their recorded scope; newly discovered conflicts require separate mediation.