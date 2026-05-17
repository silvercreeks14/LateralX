# 00_Quick_Demo — Single-Event Rule Verification Files

Minimal JSON files for smoke-testing individual AD detection rules. Each file
contains the smallest event set needed to fire one specific rule. Import any of
these in a new case to verify a rule fires and the correct MITRE technique appears.

## Files

| File | Rule triggered | MITRE | Notes |
|---|---|---|---|
| `demo_zerologon.json` | KERB-013 Zerologon CVE-2020-1472 | T1210 | Anonymous LOGON (type 3) + 3× EID 4742 machine-account-changed on same DC within 1 min |
| `demo_token_impersonation.json` | PRIV-012 Token Impersonation Chain | T1134.001 | EID 4624 + EID 4674 with SeImpersonatePrivilege for same user |
| `demo_wdigest_renable.json` | CRED-007 WDigest Plaintext Caching | T1112 | EID 4657 registry write to `UseLogonCredential` = 1 |

## How to use

1. Open LateralX and create a new case (e.g., "Rule Smoke Test").
2. Upload one of these JSON files.
3. Run **Analyze → AD Intelligence** — the matching rule should appear under "Detections".
4. Verify the MITRE technique, severity, and evidence text.

These files are not realistic attack scenarios. For full multi-phase scenarios, see
folders `01_AD_Full_Attack_Chain` through `11_APT29_Full_Chain`.
