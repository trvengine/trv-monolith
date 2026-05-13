# TRV™ Cryptographic Engine (TRVEngine™) License (TCEL)

## 1. Definitions

### 1.1 “Software” and Identity Definitions
*   **“TRV™”** refers to the **TRV™ Cryptographic Engine (TRVEngine™)**.
*   **“BTGS”** refers to the **Boolean Transformation Gate System** defined by the relations:
    *   **Math:** x = ¬(a ⊕ b), y = (a ∧ ¬c) ∨ (¬b ∧ c), z = (¬b ∧ ¬c) ∨ (¬a ∧ c)
    *   **Code:** x = ~(a ^ b), y = (a & ~c) | (~b & c), z = (~b & ~c) | (~a & c)
*   **“TRV™ Labs”** refers to the authorized development, publishing, and licensing entity of the TRV ecosystem.
*   **“Software”** collectively refers to TRV™, BTGS, and all associated source code, binaries, documentation, specifications, reference implementations, and related materials.

### 1.2 “System Output”
“System Output” refers to any ciphertext, hash, authentication result, or transformed state produced by TRV™. The commercial sale, lease, or provisioning of System Output to third parties (e.g., Encryption-as-a-Service) is deemed a Commercial Use of the Software.

### 1.3 “Derivative Work”
A “Derivative Work” includes any software that:
*   Incorporates TRV™ source code directly or indirectly.
*   Reproduces BTGS logic (fully or partially) in equivalent form.
*   Replicates TRV™ state transition behavior or transformation rules.
*   Reimplements TRV™ behavior in any programming language or hardware description.

**Clarification:** Reimplementation counts as derivative even if no original code is copied, if functional equivalence exists. Any work incorporating any component of the coupled logic relations (x, y, z) defined in the BTGS is classified as a Derivative Work.

### 1.4 “Commercial Use”
“Commercial Use” includes any use of TRV™ or Derivative Works that is intended to:
*   Generate revenue directly or indirectly.
*   Support a paid product or service.
*   Be embedded in proprietary software, firmware, or hardware.
*   Be used in enterprise, institutional, or government paid infrastructure.
*   Be offered as part of a paid API, SaaS, or hosted system.
*   Reduce operational cost in a revenue-generating system.

**Clarification:**
Internal corporate or organizational use is considered Commercial Use if it supports, directly or indirectly:
*   A revenue-generating product or service,
*   Proprietary infrastructure,
*   Internal operational systems,
*   Organizational communications,
*   Or secured data processing.

Any use of TRV™ by a for-profit entity, governmental entity, institutional entity, or non-profit organization for operational, infrastructural, or security-related purposes shall be deemed Commercial Use by default unless explicitly authorized in writing by the author or TRV™ Labs.

### 1.5 “Non-Commercial Use”
Non-commercial use includes:
*   Personal experimentation.
*   Academic research.
*   Independent cryptographic analysis.
*   Educational use.
*   Security testing without production deployment.

### 1.6 Content Creation and Public Discussion
Subject to this License, third parties are permitted to create and publish educational material, technical analysis, benchmarks, reviews, demonstrations, commentary, research publications, and media content related to TRV™, BTGS, or associated implementations.

Such content must:
*   Provide clear attribution to **TRV™** and **TRV™ Labs**.
*   Not falsely claim ownership of the Software.
*   Not misrepresent official affiliation or endorsement.
*   Not redistribute proprietary source code beyond the permissions granted in this License.

## 2. License Grant (Non-Commercial Only)
Permission is granted to use, copy, and analyze the Software solely for Non-Commercial Use under the following conditions:
*   Attribution to **TRV™ Labs** is required.
*   This license must be included in all copies.
*   No removal or obfuscation of origin is permitted.

## 3. Commercial Restriction
No Commercial Use is permitted without a separate written commercial license from **TRV™ Labs**. Commercial use includes any direct or indirect integration, deployment, or reliance on TRV™ or its Derivative Works in a revenue-generating context.

## 4. Prohibition of Circumvention
It is prohibited to:
*   Bypass licensing restrictions through reimplementation of BTGS or TRV™ logic.
*   Extract, reverse engineer, or reconstruct equivalent functional behavior for Commercial Use.
*   Distribute modified versions intended to replicate TRV™ functionality.

## 5. Intellectual Property Ownership & Patent Reservation
The **TRV™ Cryptographic Engine (TRVEngine™)**, including BTGS and all associated implementations, designs, transformations, documentation, and reference materials, is the exclusive intellectual property of **Ihentuge Uchechukwu**, founder of **TRV™ Labs**.

### 5.1 Patent and Hardware Reservation
No patent rights, implied licenses, or rights to manufacture proprietary derivative systems are granted under this License. **Ihentuge Uchechukwu** and **TRV™ Labs** reserve all rights related to:
*   Cryptographic transformations and Boolean state systems.
*   Execution architectures and circuit implementations.
*   Hardware acceleration methods (FPGA, ASIC, etc.).
*   Derivative cryptographic constructions related to BTGS or TRV™.

### 5.2 Contributors and Collaborators
Any listed development partners, contributors, or collaborators do not acquire ownership rights to the TRV™ intellectual property unless explicitly stated in a separate written agreement. Contributions, patches, analysis, or implementation assistance submitted by third parties do not transfer ownership of the TRV™ system or BTGS core unless explicitly agreed in writing by **Ihentuge Uchechukwu**.

## 6. Security, Export, and Certification Disclaimer
TRV™ is provided “as is,” without warranties of any kind. 

### 6.1 No Certification or Official Guarantee
Use, publication, or availability of TRV™ does not imply:
*   Governmental approval or industry certification.
*   Formal security accreditation or endorsement by any standards organization.

### 6.2 Export and Legal Compliance
Users are responsible for compliance with all applicable laws, regulations, and export restrictions relating to cryptographic software in their jurisdiction. **TRV™ Labs** assumes no responsibility for unlawful use or deployment of the Software.

## 7. Attribution and Citation Standard
Any publication, analysis, or implementation referencing this system must include:
**“TRV™ Cryptographic Engine (TRVEngine™) — developed by TRV™ Labs”**  
**“Core transformation: BTGS (Boolean Transformation Gate System)”**

## 8. Ecosystem Principle
TRV™ is defined as a self-contained cryptographic ecosystem built from a single transformation core. External cryptographic standards are not required for interpretation or execution of the system.

## 9. Governing Law and Jurisdiction
This License shall be governed by the laws of a jurisdiction to be determined by the Licensor. Until such determination is made, disputes shall be resolved in a jurisdiction reasonably connected to the Licensor or **TRV™ Labs**.

## 10. Trademark Restriction
This License does not grant permission to use **TRV™**, **TRVEngine™**, **BTGS**, or **TRV™ Labs** as product names, branding identifiers, or commercial marks without explicit written authorization. Use of these trademarks in media or promotional materials does not imply partnership, endorsement, or authorization.

## 11. Reserved Rights and Versioning
All rights not explicitly granted under this License are reserved by **Ihentuge Uchechukwu** and **TRV™ Labs**.

### 11.1 License Versioning
**TRV™ Labs** may publish updated versions of this License for future releases. Previously released versions remain governed by the License version distributed with those releases unless otherwise agreed in writing.

### 11.2 Verification of Authority
Any entity claiming to be **TRV™ Labs** or an authorized representative must be explicitly designated as such in a written instrument signed by **Ihentuge Uchechukwu**. Any license, grant, or agreement issued by a third party or a corporate entity claiming to represent the TRV™ ecosystem without the Author's verified designation is null and void *ab initio*. 

## 12. Licensing Contact
For inquiries regarding commercial licensing, partnerships, or official authorization, contact the Author or **TRV™ Labs** via the official website:
**https://www.trvengine.com**

---
*Copyright (c) 2026 Ihentuge Uchechukwu. All Rights Reserved. TRV™ and TRVEngine™ are trademarks owned by Ihentuge Uchechukwu, founder of TRV™ Labs.*
