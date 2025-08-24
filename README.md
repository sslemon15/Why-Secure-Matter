# Matter OTA Update Protocol - Formal Security Analysis

## Overview

This repository contains a formal security analysis of the Matter OTA (Over-The-Air) update protocol using ProVerif. The analysis models the protocol's communication channels, cryptographic operations, and security properties.

## Model Architecture

### Core Components

The ProVerif model (`cis.pv`) implements the following key components:

1. **Vendor**: Code signing authority that signs firmware images
2. **Provider**: OTA server that distributes firmware updates
3. **Requestor**: Device requesting firmware updates

### Cryptographic Primitives

- **AEAD Encryption**: Authenticated encryption with associated data
- **Digital Signatures**: ECDSA-style signatures for code authenticity
- **Hash Functions**: For integrity verification
- **Nonce Generation**: Structured as SecurityFlags || MessageCounter || SourceNodeID

### Communication Model

The protocol uses secure channels modeling Matter's CASE (Certificate Authenticated Session Establishment):
- Bidirectional keys: `k_i2r` (Initiator to Responder) and `k_r2i` (Responder to Initiator)
- Session identifiers and message counters for replay protection
- Structured AAD (Additional Authenticated Data) for message layer security

## Protocol Flow

### 1. Query Phase
- Requestor sends `QueryImage` with device identifiers (VID, PID, current version)
- Provider responds with `QueryImageResponse` containing new version and update token

### 2. Download Phase  
- Provider sends firmware image with digest and vendor signature
- Requestor verifies signature against vendor's public key
- Image integrity checked via hash comparison

### 3. Apply Phase
- Requestor sends `ApplyUpdateRequest` with update token
- Provider responds with action (PROCEED/AWAIT) and delay
- Requestor notifies completion

## Security Properties Verified

### ✅ **Confidentiality**
```
RESULT not attacker(FWIMG[]) is true.
```
**Property**: The firmware image remains confidential - attackers cannot obtain firmware content.

### ✅ **Download Authenticity**
```
RESULT event(DownloadDone(r_1,p,u,f)) ==> event(DownloadStart(p,u,f)) is true.
```
**Property**: Every successful download corresponds to an actual download initiation by the provider.

### ✅ **Message Authenticity with Injective Agreement**
```
RESULT inj-event(DownloadDone(r_1,p,u,f)) ==> inj-event(SendR2I(sid_3,ctr,M_DL(...))) is true.
```
**Property**: Each download completion corresponds to exactly one authentic message transmission from the provider, preventing replay attacks.

### ✅ **Protocol Ordering**
```
RESULT event(DownloadStart(p,u,f)) ==> event(QueryAnsweredP(p,vid_1,pid_1,nsv_1)) is true.
```
**Property**: Downloads only start after a valid query response, ensuring proper protocol sequencing.

### ✅ **Message Uniqueness** 
```
RESULT event(RecvI2R(sid0,ctr0,m1)) && event(RecvI2R(sid0,ctr0,m2)) ==> m1 = m2 is true.
RESULT event(RecvR2I(sid1,ctr1,n1)) && event(RecvR2I(sid1,ctr1,n2)) ==> n1 = n2 is true.
```
**Property**: Same session ID and counter always correspond to identical messages, preventing confusion attacks.

### ✅ **Injective Message Authentication**
```
RESULT inj-event(RecvI2R(sid2,ctr2,m_1)) ==> inj-event(SendI2R(sid2,ctr2,m_1)) is true.
RESULT inj-event(RecvR2I(sid3,ctr3,n)) ==> inj-event(SendR2I(sid3,ctr3,n)) is true.
```
**Property**: Every received message corresponds to exactly one sent message, providing strong replay protection.

## Key Security Features Modeled

### 1. **Code Signing Chain**
- Vendor maintains private signing key `KM_VENDOR`
- Firmware images signed with `sign(hash(FWIMG), sk(KM_VENDOR))`
- Signature verification prevents unauthorized firmware

### 2. **Secure Channel Properties**
- CASE-like authenticated encryption
- Session-specific key derivation
- Structured nonces prevent replay attacks

### 3. **Token-Based Authorization**
- Update tokens bind query responses to apply requests
- Prevents unauthorized firmware installation
- Session-scoped token validity

### 4. **Version Control**
- Abstract version comparison `ver_gt(NEW(), CUR()) = ok()`
- Prevents downgrade attacks

## Threat Model

The analysis assumes:
- **Dolev-Yao attacker**: Can intercept, modify, and inject messages on public channels
- **Honest parties**: Vendor, Provider, and Requestor follow the protocol
- **Secure channels**: Private channels (vendor-to-provider) are secure
- **Cryptographic assumptions**: Standard assumptions about AEAD, signatures, and hashes

## Verification Results Summary

All critical security properties hold:

| Property | Status | Description |
|----------|---------|-------------|
| Firmware Confidentiality | ✅ **VERIFIED** | Firmware content remains secret |
| Download Authenticity | ✅ **VERIFIED** | Downloads originate from legitimate providers |
| Message Authentication | ✅ **VERIFIED** | All messages are authentic with replay protection |
| Protocol Ordering | ✅ **VERIFIED** | Correct sequencing of protocol phases |
| Token Binding | ✅ **VERIFIED** | Update tokens properly bind operations |

## Model Limitations

1. **Abstract Cryptography**: Uses symbolic cryptography (Dolev-Yao model)
2. **Simplified Version Logic**: Abstract version comparison predicates
3. **Single Firmware**: Models one firmware image per session
4. **No Network Partitions**: Assumes reliable message delivery on secure channels

## Files Structure

- `models/cis.pv`: Main ProVerif model file
- `models/cis.out.txt`: Verification results and detailed traces  
- `models/crypto_primitives.pv`: Cryptographic function definitions (if used)
- `docs/security-analysis-report.md`: Detailed technical analysis report
- `docs/security-properties.md`: Complete security properties documentation
- `properties/`: Security property query files (if separate)
- `scenarios/`: Protocol scenario definitions (if separate)

## Documentation

📋 **[Security Analysis Report](docs/security-analysis-report.md)** - Comprehensive technical analysis  
🔒 **[Security Properties](docs/security-properties.md)** - Detailed property documentation  
📊 **[Verification Results](models/cis.out.txt)** - Raw ProVerif output with traces

## Quick Start

## Quick Start

```bash
# Clone the repository
git clone https://github.com/sslemon15/matter-ota-proofs.git
cd matter-ota-proofs

# Verify all properties
proverif models/cis.pv

# Generate detailed output
proverif models/cis.pv > models/cis.out.txt 2>&1

# Parse-only check
proverif -parse-only models/cis.pv
```

## Results Summary

🔒 **All security properties verified successfully**

| Property Category | Status | 
|------------------|---------|
| Firmware Confidentiality | ✅ VERIFIED |
| Message Authentication | ✅ VERIFIED |  
| Replay Protection | ✅ VERIFIED |
| Protocol Ordering | ✅ VERIFIED |
| Token Authorization | ✅ VERIFIED |

## Conclusion

The formal analysis demonstrates that the Matter OTA protocol, when implemented with proper cryptographic protections (CASE secure channels, code signing, replay protection), provides strong security guarantees for firmware distribution. All critical properties including confidentiality, authenticity, and integrity are verified to hold against Dolev-Yao attackers.
