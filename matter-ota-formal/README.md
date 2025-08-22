# Matter OTA Protocol Formal Verification

##  Overview

This project implements formal verification of security properties of the Matter Over-The-Air (OTA) update protocol using **ProVerif**.

##  Project Structure

```
matter-ota-formal/
├──  docs/                    # Detailed documentation
│   └── mapping_matter_to_proverif.md
├──  models/                  # ProVerif models
│   ├── crypto_primitives.pv
│   ├── secure_channels_case_pase.pv
│   ├── ota_cluster_provider.pv
│   ├── ota_cluster_requestor.pv
│   ├── bdx_protocol.pv
│   └── dcl_interface_assumptions.pv
├──  scenarios/               # Test scenarios
│   ├── main_ota_standard_case.pv
│   ├── main_ota_resumption_case.pv
│   └── adversary_leaks_scenarios.pv
├──  properties/              # Security queries
│   ├── queries_conf_auth.pv
│   ├── queries_privacy.pv
│   └── queries_resumption.pv
|
├──  outputs/                 # Verification results
│   └── .gitkeep
|__
```



##  Verified Properties

###  Confidentiality


###  Authenticity  


###  Integrity


###  Privacy


##  Documentation

- **[Complete Guide](docs/mapping_matter_to_proverif.md)**: Detailed documentation of Matter → ProVerif mapping
- **Models**: Each `.pv` file contains explanatory comments
- **Scenarios**: Test case descriptions in `scenarios/`

##  Usage

### Single Test
```bash
# Verify specific model
proverif models/ota_cluster_provider.pv

# With detailed output
proverif -html -o outputs/report.html models/ota_cluster_provider.pv
```

### Scenario Testing
```bash
# Standard scenario
proverif scenarios/main_ota_standard_case.pv

# Adversarial scenario
proverif scenarios/adversary_leaks_scenarios.pv
```

### Debugging
For detailed traces, add to `.pv` files:
```proverif
set traceDisplay = long.
set verboseRules = explained.
```


##  Support

- **Documentation**: [docs/mapping_matter_to_proverif.md](docs/mapping_matter_to_proverif.md)
- **ProVerif Manual**: [Official Documentation](https://prosecco.gforge.inria.fr/personal/bblanche/proverif/)
- **Matter Core Specification 1.4**: [CSA Alliance](https://csa-iot.org/developer-resource/specifications-download-request/)
- 
---

**Status**: In Development  
**Last Updated**: August 2025  
**ProVerif Version**: 2.05+
