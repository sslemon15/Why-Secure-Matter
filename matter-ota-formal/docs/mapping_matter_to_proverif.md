# Mapping Matter OTA Protocol to ProVerif

## Table of Contents

1. [Project Overview](#project-overview)
2. [Matter OTA Protocol Architecture](#matter-ota-protocol-architecture)
3. [ProVerif Modeling](#proverif-modeling)
4. [Cryptographic Primitives](#cryptographic-primitives)
5. [Verification Scenarios](#verification-scenarios)
6. [Security Properties](#security-properties)
7. [Results and Analysis](#results-and-analysis)
8. [Usage Guide](#usage-guide)

## Project Overview

### Objective

Formal verification of security properties of the Matter Over-The-Air (OTA) update protocol using ProVerif.

### Scope

- **Confidentiality**: Update data is protected on-wire during transfer
- **Authenticity**: Updates come from authorized sources
- **Integrity**: Data is not altered during transfer
- **Privacy (on-wire)**: Device metadata is not leaked in clear on the transport

### Methodology

- Formal modeling of protocol components
- Definition of attack scenarios
- Automatic property verification via ProVerif

## Matter OTA Protocol Architecture

### Main Components

#### OTA Provider
```
Role: Provides firmware updates
Functions:
- Manages update catalog
- Authenticates requestors (operational CASE)
- Transmits firmware data (BDX over PASE or CASE)
```

#### OTA Requestor
```
Role: Requests and receives updates
Functions:
- Checks update availability
- Authenticates provider (operational CASE)
- Downloads and validates firmware (BDX over PASE or CASE)
```

#### Secure Transport (PASE / CASE)
- BDX SHALL run only inside a PASE or CASE encrypted session (Spec §11.22.4).
- OTA control-plane (QueryImage, ApplyUpdateRequest, NotifyUpdateApplied) is a normal cluster interaction subject to Access Control; in practice it's done over CASE because operational ACLs do not authorize via PASE.
- BDX can ride on BTP/TCP/MRP as long as it is inside PASE/CASE (Spec §11.22.4).



## ProVerif Modeling

### File Structure

```
models/
├── crypto_primitives.pv             # Basic crypto (hash, AEAD, signatures)
├── secure_channels_case_pase.pv     # Session/key schedule abstractions
├── ota_cluster_provider.pv          # OTA Provider control-plane
├── ota_cluster_requestor.pv         # OTA Requestor control-plane
├── bdx_protocol.pv                  # Bulk Data Exchange (data-plane)
└── dcl_interface_assumptions.pv     # DCL assumptions (non-normative)
```

### Naming Conventions

#### Data Types

- `deviceId` — unique device identifier
- `firmwareVersion` — firmware version (scalar)
- `firmwareData` — firmware payload
- `signature` — digital signature
- `certificate` — digital certificate

#### Channels

- `c` — public Dolev–Yao channel (attacker-controlled).


#### Processes

- `Provider()` — OTA provider process
- `Requestor()` — OTA requestor process
- `Adversary()` — optional attacker helpers

## Cryptographic Primitives

### Hash
```proverif
fun hash(bitstring): bitstring.
```

### AEAD (Authenticated Encryption with Associated Data)
```proverif
type key.
fun aead_enc(key, bitstring, bitstring, bitstring): bitstring.
(* m, nonce, ad -> ciphertext *)
reduc forall k: key, m: bitstring, n: bitstring, ad: bitstring;
      aead_dec(k, aead_enc(k, m, n, ad), n, ad) = m.
```

AEAD sostituisce i modelli "senc/sdec" e cattura riservatezza e integrità on-wire.

### Digital Signatures
```proverif
fun pk(bitstring): bitstring.
fun sign(bitstring, bitstring): bitstring.
fun verify(bitstring, bitstring, bitstring): bool.
equation forall m: bitstring, sk: bitstring;
  verify(sign(m, sk), m, pk(sk)) = true.
```

(Opzionale: KDF, MAC, commitment, se servono nei modelli di chiavi di sessione/resumption.)

## Verification Scenarios

### Standard Scenario (CASE control-plane, BDX in CASE)

**File**: `scenarios/main_ota_standard_case.pv`
- Honest Provider/Requestor
- CASE established
- BDX transfer under CASE
- Normal firmware validation

### Resumption Scenario

**File**: `scenarios/main_ota_resumption_case.pv`
- Transfer interruption
- Resume from correct offset/range
- Integrity preserved across sessions

### Attack Scenarios

**File**: `scenarios/adversary_leaks_scenarios.pv`
- Active MITM on c
- Partial key compromise (session key leak, but not long-term keys)
- Replay / reordering attempts (BDX counters)

(Facoltativo [magarri successivamente]: includere una variante BDX over PASE per coprire la condizione normativa di §11.22.4.)

## Security Properties

### Confidentiality & Integrity (on-wire)

**File**: `properties/queries_conf_auth.pv`
```proverif
(* The attacker must not learn plaintext firmware transmitted on-wire *)
query attacker(firmware_plain_onwire).

(* Session keys and long-term private keys stay secret *)
query attacker(session_key).
query attacker(provider_sk).
query attacker(requestor_sk).
```

### Authenticity / Authorization (control-plane → data-plane)
```proverif
event ProviderAuthorized(deviceId, providerNodeId).
event FirmwareReceived(deviceId, firmwareData, providerNodeId).

(* If Requestor accepts firmware as from providerNodeId, then that provider was authorized *)
query d: bitstring, f: bitstring, p: bitstring;
  event(FirmwareReceived(d, f, p)) ==> event(ProviderAuthorized(d, p)).
```

### Privacy (on-wire)

**File**: `properties/queries_privacy.pv`
```proverif
(* Device identity and version MUST NOT appear in clear on-wire payloads *)
query attacker(deviceId_onwire_clear).
query attacker(version_onwire_clear).
```



## Results and Analysis

### ProVerif Results Interpretation

- **RESULT is true** — 
- **RESULT is false** — 
- **RESULT cannot be proved** — 

## Usage Guide

### Prerequisites (use opam for portability)
```bash
sudo apt update
sudo apt install -y build-essential m4 opam graphviz make git
opam init -y --auto-setup
opam switch create 4.14.2 ocaml-base-compiler.4.14.2
eval $(opam env)
opam install -y proverif
proverif --version
```


### Running Tests

#### Single file
```bash
proverif models/crypto_primitives.pv
```

#### HTML trace
```bash
proverif -html models/crypto_primitives.pv
# genera models/crypto_primitives.html
```



### Debugging and Analysis

All'inizio del `.pv`:
```proverif
set traceDisplay = long.
```



### Spec Pointers 

- **BDX security & transports**: §11.22.4 — "BDX SHALL only be executed over PASE or CASE encrypted session."
- **OTA Provider/Requestor commands & ImageURI (BDX/HTTPS)**: §11.20.6.5
- **OTA Image file (header/digest)**: §11.21.2
- **DCL overview & schemas**: §11.23

---

**Version**: 1.0  
**Date**: August 2025  
**Author**: Simone Sambataro — Matter OTA Verification Project
