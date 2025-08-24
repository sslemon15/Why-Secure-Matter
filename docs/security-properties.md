# Security Properties and Query Documentation

## Overview
This document details the formal security properties verified in the Matter OTA protocol analysis using ProVerif.

## Property Categories

### 1. Confidentiality Properties

#### Firmware Content Protection
```proverif
query attacker(FWIMG).
```
**Expected Result**: `false` (attacker should NOT be able to obtain firmware)  
**Actual Result**: ✅ `RESULT not attacker(FWIMG[]) is true.`

**Interpretation**: The firmware image marked as `[private]` cannot be derived by the attacker through any combination of protocol messages and cryptographic operations.

---

### 2. Authentication Properties

#### Download Origin Authentication
```proverif
query r:bitstring, p:bitstring, u:bitstring, f:bitstring;
  event(DownloadDone(r, p, u, f)) ==> event(DownloadStart(p, u, f)).
```
**Result**: ✅ **VERIFIED**

**Interpretation**: Every completed download must originate from a legitimate download initiation by the provider, ensuring no unauthorized firmware can be marked as "successfully downloaded."

#### Strong Message Authentication (Injective)
```proverif
query r:bitstring, p:bitstring, u:bitstring, f:bitstring, sid:bitstring, ctr:bitstring;
  event(DownloadDone(r, p, u, f))
  ==> inj-event(SendR2I(sid, ctr, M_DL(u, f, hash(f), sign(hash(f), sk(KM_VENDOR))))).
```
**Result**: ✅ **VERIFIED with injective correspondence**

**Interpretation**: Each download completion corresponds to exactly one authentic message transmission containing the proper vendor signature and hash verification.

---

### 3. Protocol Ordering Properties

#### Query-Before-Download Enforcement
```proverif
query p:bitstring, vid:bitstring, pid:bitstring, nsv:bitstring, u:bitstring, f:bitstring;
  event(DownloadStart(p, u, f)) ==> event(QueryAnsweredP(p, vid, pid, nsv)).
```
**Result**: ✅ **VERIFIED**

**Interpretation**: Downloads can only begin after a proper query-response handshake, preventing unauthorized firmware distribution bypass.

---

### 4. Message Uniqueness and Anti-Replay

#### Session-Counter Message Uniqueness
```proverif
query sid0:bitstring, ctr0:bitstring, m1:bitstring, m2:bitstring;
  event(RecvI2R(sid0, ctr0, m1)) && event(RecvI2R(sid0, ctr0, m2)) ==> m1 = m2.

query sid1:bitstring, ctr1:bitstring, n1:bitstring, n2:bitstring;
  event(RecvR2I(sid1, ctr1, n1)) && event(RecvR2I(sid1, ctr1, n2)) ==> n1 = n2.
```
**Result**: ✅ **VERIFIED for both directions**

**Interpretation**: The same session ID and message counter always correspond to identical plaintext content, preventing confusion attacks within sessions.

#### Injective Message Correspondence
```proverif
query sid2:bitstring, ctr2:bitstring, m:bitstring;
  event(RecvI2R(sid2, ctr2, m)) ==> inj-event(SendI2R(sid2, ctr2, m)).

query sid3:bitstring, ctr3:bitstring, n:bitstring;
  event(RecvR2I(sid3, ctr3, n)) ==> inj-event(SendR2I(sid3, ctr3, n)).
```
**Result**: ✅ **VERIFIED with injective correspondence**

**Interpretation**: Every received message corresponds to exactly one sent message, providing strong replay protection and ensuring message freshness.

---

### 5. Token-Based Authorization Properties

#### Apply Request Authentication
```proverif
query sid:bitstring, tok:bitstring, act:bitstring;
  event(ApplyRespRcv(sid, tok, act)) ==> inj-event(ApplyReqSent(sid, tok)).
```
**Result**: ✅ **VERIFIED**

**Interpretation**: Apply responses can only be received after sending corresponding apply requests with valid tokens.

#### Token Issuance Binding
```proverif
query sid:bitstring, tok:bitstring;
  event(ApplyReqSent(sid, tok)) ==> event(TokenIssuedSID(sid, tok)).
```
**Result**: ✅ **VERIFIED**

**Interpretation**: Update tokens can only be used in apply requests if they were properly issued during the query phase.

#### Token Uniqueness (Cross-Session)
```proverif
query s1:bitstring, s2:bitstring, tok:bitstring;
  event(TokenIssuedSID(s1, tok)) && event(TokenIssuedSID(s2, tok)) ==> s1 = s2.
```
**Result**: ✅ **VERIFIED**

**Interpretation**: Update tokens are unique across sessions, preventing token reuse attacks.

---

### 6. Reachability Properties (Sanity Checks)

#### Protocol Completion
```proverif
query event(endP()).  (* Provider completes successfully *)
query event(endR()).  (* Requestor completes successfully *)
```
**Result**: ✅ **BOTH REACHABLE**

**Interpretation**: The protocol can successfully complete under normal conditions, confirming the model is not over-constrained.

---

## Cryptographic Assumptions

The verification relies on standard cryptographic assumptions:

### AEAD Security
```proverif
fun aead_enc(key, bitstring, bitstring, bitstring): bitstring.
reduc forall k: key, m: bitstring, n: bitstring, ad: bitstring;
  aead_dec(k, aead_enc(k, m, n, ad), n, ad) = m.
```
**Assumption**: AEAD provides IND-CCA2 confidentiality and INT-CTXT integrity

### Digital Signature Security
```proverif
reduc forall m:bitstring, y:keymat; 
  checksign(sign(m, sk(y)), pk(y)) = ok().
```
**Assumption**: Digital signatures provide EUF-CMA security

### Hash Function Security
```proverif
fun hash(bitstring) : bitstring.
```
**Assumption**: Hash functions are collision-resistant and provide integrity

---

## Attack Scenarios Tested

### 1. **Eavesdropping Attack**
- **Goal**: Extract firmware content from network traffic
- **Result**: ❌ **FAILED** - Firmware remains confidential

### 2. **Firmware Injection Attack**  
- **Goal**: Inject unauthorized firmware
- **Result**: ❌ **FAILED** - Signature verification prevents injection

### 3. **Replay Attack**
- **Goal**: Replay previous messages to trigger actions
- **Result**: ❌ **FAILED** - Injective correspondence prevents replay

### 4. **Session Confusion Attack**
- **Goal**: Mix messages between different sessions
- **Result**: ❌ **FAILED** - Session binding enforced

### 5. **Protocol Phase Skip Attack**
- **Goal**: Bypass query phase and directly download
- **Result**: ❌ **FAILED** - Protocol ordering enforced

### 6. **Token Reuse Attack**
- **Goal**: Reuse update tokens across sessions
- **Result**: ❌ **FAILED** - Token uniqueness enforced

---

## Verification Statistics

**Total Queries**: 11 security properties + 2 reachability checks  
**Verification Status**: ✅ **ALL PASSED**  
**Rules Generated**: ~200 Horn clauses  
**Analysis Time**: < 1 second  
**ProVerif Version**: 2.05

---

## Interpretation Guidelines

### ✅ **RESULT [...] is true**
Property holds - no counterexample found. The protocol satisfies this security requirement.

### ❌ **RESULT [...] is false** 
Property violated - counterexample exists. Would indicate a security vulnerability.

### 🔍 **goal reachable: [trace]**
Shows example execution trace where the property holds, useful for understanding protocol flow.

### ⚡ **Injective correspondence**
Stronger than simple correspondence - ensures one-to-one mapping between events, preventing replay attacks.

---

*This analysis provides formal guarantees under the Dolev-Yao threat model with perfect cryptography assumptions.*
