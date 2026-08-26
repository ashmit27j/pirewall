# pirewall — MASTER IMPLEMENTATION SPECIFICATION

Build **pirewall**, an AI-assisted adaptive network firewall running on a Raspberry Pi 4.

The system must be secure, modular, type-safe, testable, resource-efficient, and deployable on a real Raspberry Pi.

---

# 1. PURPOSE

pirewall operates as a network gateway/firewall.

It:

* captures network traffic
* converts packets into flows
* extracts canonical features
* detects known attacks with LightGBM
* detects anomalies with Isolation Forest
* performs deterministic behavioral analysis
* calculates a threat score
* makes firewall decisions
* generates candidate firewall rules
* validates candidate rules
* deploys approved rules
* reports security events to an Admin PC
* provides a secure local control panel

Runtime inference and firewall decisions must operate locally on the Raspberry Pi.

No cloud service, external AI API, LLM, or remote inference is required for runtime operation.

---

# 2. ARCHITECTURE

```text
                         INTERNET
                            |
                            v
                       HOME ROUTER
                            |
                            v
                    +---------------+
                    |    pirewall   |
                    | Raspberry Pi  |
                    |               |
                    | Packet Capture|
                    | Flow Engine   |
                    | Feature Engine|
                    | ML Detection  |
                    | Threat Engine |
                    | Firewall      |
                    | API           |
                    | Control Panel |
                    +-------+-------+
                            |
                            v
                       PROTECTED LAN
                            |
                +-----------+-----------+
                |                       |
                v                       v
           Client Devices           Admin PC
                                      |
                              +-------+-------+
                              |               |
                              v               v
                            Wazuh          Netdata
```

The Raspberry Pi is the network enforcement point.

It must handle:

* WAN traffic
* LAN traffic
* forwarding
* firewall enforcement
* packet observation
* flow aggregation
* threat detection
* adaptive rules

The network topology must be configurable.

Do not hard-code interface names.

---

# 3. HARDWARE

Primary target:

**Raspberry Pi 4, 4 GB RAM**

The Pi is dedicated primarily to pirewall.

Runtime requirements:

* bounded memory
* bounded flow state
* bounded queues
* efficient packet processing
* no GPU dependency
* no cloud dependency
* no unnecessary database
* no message broker
* no heavyweight runtime infrastructure

---

# 4. DEVELOPMENT VS RUNTIME

## Development machine

Used for:

* dataset processing
* feature engineering
* model training
* model evaluation
* model serialization
* benchmarks

## Raspberry Pi

Used for:

* packet capture
* packet parsing
* flow aggregation
* feature extraction
* ML inference
* behavioral analysis
* threat assessment
* firewall decisions
* rule generation
* rule validation
* firewall enforcement
* API
* control panel
* event forwarding

Models are trained on the development machine and deployed to the Pi.

Do not train production models on the Pi.

---

# 5. CORE PIPELINE

```text
RAW NETWORK TRAFFIC
        |
        v
PACKET CAPTURE
        |
        v
PACKET PARSING
        |
        v
FLOW AGGREGATION
        |
        v
CANONICAL FLOW
        |
        v
FEATURE EXTRACTION
        |
        v
CANONICAL FEATURE VECTOR
        |
        +----------------------+
        |                      |
        v                      v
    LightGBM            Isolation Forest
        |                      |
        v                      v
Known Attack Evidence    Anomaly Evidence
        |                      |
        +----------+-----------+
                   |
                   v
            BEHAVIOR ANALYSIS
                   |
                   v
            THREAT ASSESSMENT
                   |
                   v
              THREAT SCORE
                   |
                   v
            FIREWALL DECISION
                   |
          +--------+--------+
          |                 |
          v                 v
        ALLOW              BLOCK
                              |
                              v
                       CANDIDATE RULE
                              |
                              v
                       RULE VALIDATION
                              |
                       +------+------+
                       |             |
                     VALID        INVALID
                       |             |
                       v             v
                    DEPLOY         REJECT
                       |
                       v
                SECURITY EVENT
                       |
                +------+------+
                |             |
                v             v
              Wazuh       Control Panel
```

ML output must never directly execute firewall commands.

---

# 6. PACKET CAPTURE

Use:

**Linux AF_PACKET / libpcap-style packet capture**

Do not use:

* eBPF
* BCC
* Scapy as the capture foundation
* payload inspection as the core architecture

Create a capture abstraction:

```text
PacketCapture
    |
    +-- AF_PACKET implementation
    |
    +-- Test implementation
```

The capture subsystem must:

* bind to a configured interface
* capture required traffic
* expose packet metadata
* handle malformed packets
* handle unsupported packets
* support graceful shutdown
* expose capture statistics
* detect packet drops where possible
* avoid retaining raw packets unnecessarily

---

# 7. PACKET PARSING

Parse only information required by the detection architecture.

Support the required:

* Ethernet
* IPv4
* IPv6 where implemented
* TCP
* UDP
* ICMP/ICMPv6 where relevant

TCP information should include:

* source port
* destination port
* SYN
* ACK
* FIN
* RST
* PSH
* URG

Malformed or truncated packets must never crash pirewall.

Do not perform application-payload inspection as part of the core detection pipeline.

---

# 8. FLOW AGGREGATION

Convert packets into canonical flows.

Flow identity should use:

```text
source IP
destination IP
source port
destination port
protocol
```

Bidirectional traffic must be normalized consistently.

Track:

* first timestamp
* last timestamp
* duration
* packet count
* byte count
* forward packet count
* backward packet count
* forward byte count
* backward byte count
* TCP flag counts
* packet-size statistics
* inter-arrival statistics

Support:

* active timeout
* inactive timeout
* flow completion
* bounded flow table
* eviction
* graceful shutdown

The flow table must never grow without bounds.

---

# 9. DOMAIN MODELS

Create strongly typed domain models for:

```text
Flow
FeatureVector
KnownEvidence
AnomalyEvidence
BehaviorAssessment
ThreatAssessment
FirewallDecision
FirewallRule
CandidateRule
SecurityEvent
ModelMetadata
```

Use Pydantic v2 where appropriate.

Models must have:

* explicit fields
* strict validation
* meaningful constraints
* serialization
* stable schemas
* clear semantics

Do not pass arbitrary untyped dictionaries through the core system.

---

# 10. TYPE SAFETY

Type safety is mandatory.

Use:

* Python 3.12+
* strict type annotations
* typed function parameters
* typed return values
* typed class attributes
* Pydantic models for validated external data
* `Enum`/`StrEnum` for finite values
* `Literal` where appropriate
* typed protocols/interfaces for replaceable components
* explicit nullable types
* generic types where useful

Avoid:

```python
Any
```

unless there is a documented technical reason.

Avoid:

* unchecked casts
* implicit type conversions
* untyped dictionaries
* dynamically shaped objects
* global mutable state

Use a static type checker and configure it for strict checking.

The project must pass static type checking as part of validation.

---

# 11. FEATURE EXTRACTION

Create one canonical feature-extraction layer.

```text
Canonical Flow
      |
      v
Feature Extraction
      |
      v
FeatureVector
```

Feature extraction must be deterministic.

Define:

* feature names
* types
* ordering
* units
* descriptions
* schema version

The same feature definition must be used during:

* dataset preprocessing
* training
* evaluation
* runtime inference

Do not duplicate feature calculations between training and runtime.

---

# 12. DATASETS

Use:

* CICIDS2017
* UNSW-NB15

Create dedicated adapters:

```text
CICIDS2017
     |
     v
CICIDS Adapter
     |
     v
Canonical Dataset


UNSW-NB15
     |
     v
UNSW Adapter
     |
     v
Canonical Dataset
```

Dataset-specific column names must remain inside their adapters.

Do not commit raw datasets to the repository.

---

# 13. PREPROCESSING

Dataset preprocessing must:

1. Load the source dataset.
2. Validate its schema.
3. Normalize column names.
4. Map fields to canonical features.
5. Derive required features.
6. Handle missing values.
7. Handle invalid values.
8. Validate the final schema.
9. Produce training-ready data.

Do not silently drop required features.

If a required feature cannot be produced, fail clearly.

---

# 14. MACHINE LEARNING

## LightGBM

Use LightGBM for known-attack classification.

Output:

* predicted class
* confidence/probabilities
* model version
* feature schema version

## Isolation Forest

Use Isolation Forest for anomaly detection.

An anomaly is evidence, not automatically malicious.

The ML layer produces evidence, not firewall commands.

---

# 15. MODEL ARTIFACTS

Every model must include metadata:

```text
model type
model version
training dataset
feature schema version
feature ordering
training timestamp
class mapping
preprocessing version
evaluation metrics
```

At runtime:

```text
Runtime Feature Schema
          ==
Model Feature Schema
```

If incompatible, refuse inference and report the error.

---

# 16. MODEL EVALUATION

LightGBM:

* accuracy
* precision
* recall
* F1
* confusion matrix
* per-class metrics

Isolation Forest:

* precision
* recall
* false-positive rate
* false-negative rate
* threshold behavior

Never fabricate metrics.

Clearly distinguish:

* training results
* validation results
* test results
* laboratory attack results

---

# 17. BEHAVIOR ANALYSIS

Behavior analysis is deterministic.

Analyze where applicable:

* repeated connections
* connection frequency
* burst behavior
* persistence
* destination diversity
* repeated failures
* temporal patterns
* scanning behavior

Example:

```text
Single SYN
   |
   v
Weak evidence

Repeated SYN attempts
   |
   v
Stronger evidence

Many ports / destinations
   |
   v
Possible scanning

Repeated SSH connections
   |
   v
Possible brute-force behavior
```

Behavior state must be bounded.

Do not use an LLM for runtime analysis.

---

# 18. THREAT ASSESSMENT

Combine:

* known-attack evidence
* anomaly evidence
* behavioral evidence
* repetition
* confidence
* context

Output:

* threat score
* threat level
* explanation
* contributing evidence

Use explicit threat levels:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Thresholds must be configurable.

Do not scatter magic scoring constants throughout the code.

---

# 19. FIREWALL DECISION ENGINE

Convert a threat assessment into an explicit decision.

Possible actions:

```text
ALLOW
MONITOR
RATE_LIMIT
BLOCK
```

Only implement actions supported by the backend.

A decision must contain:

* action
* threat score
* threat level
* reason
* evidence
* timestamp
* flow ID where applicable

Keep detection, decision-making, and enforcement as separate layers.

---

# 20. FIREWALL BACKEND

Use a Linux-native firewall backend.

Prefer:

**nftables**

Create an abstraction:

```text
FirewallBackend
      |
      +-- nftables implementation
      |
      +-- test implementation
```

Do not scatter firewall shell commands throughout the application.

Do not execute arbitrary commands derived from user or ML input.

---

# 21. GATEWAY CONFIGURATION

The Pi must support a configurable gateway topology.

Configuration should include where required:

```text
WAN interface
LAN interface
protected network
upstream gateway
Admin PC IP
```

Deployment must account for:

* IP forwarding
* routing
* firewall forwarding
* NAT/masquerading where required
* management access

Do not automatically modify network configuration without explicit configuration.

---

# 22. ADAPTIVE RULE PIPELINE

The adaptive firewall must use:

```text
Threat Assessment
       |
       v
Candidate Rule Generator
       |
       v
CandidateRule
       |
       v
Schema Validation
       |
       v
Safety Validation
       |
       v
Conflict Detection
       |
       v
Duplicate Detection
       |
       v
Approved FirewallRule
       |
       v
Firewall Backend
       |
       v
Audit Event
```

Never:

```text
ML output
   |
   v
shell command
   |
   v
firewall
```

---

# 23. FIREWALL RULE MODEL

Use a strongly typed model.

Fields should include where applicable:

```text
id
action
direction
source
destination
protocol
source_port
destination_port
priority
created_at
expires_at
reason
threat_score
evidence
status
metadata
```

Validate:

* IP addresses
* CIDRs
* ports
* protocols
* actions
* timestamps

---

# 24. RULE VALIDATION

Every candidate rule must be validated.

## Schema

All fields must be valid.

## Network

Validate:

* IPs
* CIDRs
* ports
* protocols
* direction

## Safety

Prevent rules from unintentionally:

* blocking pirewall itself
* blocking the Admin PC
* blocking management access
* blocking the entire protected LAN
* blocking the entire internet
* becoming broader than the evidence

## Conflict

Check existing rules.

## Duplicate

Do not repeatedly install equivalent rules.

## Priority

Check precedence and shadowing.

## Expiration

Temporary rules must support expiration.

## Authorization

Only authorized code paths may deploy rules.

Invalid rules must be rejected and recorded.

---

# 25. RULE LIFECYCLE

```text
CANDIDATE
    |
    v
VALIDATING
    |
    +------> REJECTED
    |
    v
APPROVED
    |
    v
DEPLOYED
    |
    v
ACTIVE
    |
    +------> EXPIRED
    |
    +------> DISABLED
    |
    +------> REMOVED
```

Record lifecycle changes.

Adaptive rules must not accumulate indefinitely.

---

# 26. FAIL-SAFE BEHAVIOR

Handle failures explicitly:

* capture failure
* parser failure
* flow failure
* feature failure
* model loading failure
* inference failure
* threat-engine failure
* rule-generation failure
* validation failure
* firewall failure
* API failure
* Wazuh failure

Failures must:

* be handled
* be logged
* generate appropriate events
* be visible through the control panel
* prevent unsafe rule deployment

Malformed traffic must never crash the entire system.

---

# 27. RASPBERRY PI SECURITY

The Raspberry Pi itself is a security boundary.

Secure the entire host, not only the application.

## Operating system

Use a supported Raspberry Pi OS release.

Document:

* required packages
* required updates
* required kernel/network settings
* required permissions

Do not install unnecessary services.

Disable unnecessary network services.

## Least privilege

Do not run the entire application as root unless technically unavoidable.

Separate privileged operations where practical.

Use Linux capabilities for:

* packet capture
* firewall operations
* required network operations

where appropriate.

## Service isolation

Use systemd security controls where practical:

* dedicated service user
* restricted filesystem access
* `NoNewPrivileges`
* `PrivateTmp`
* restricted capabilities
* restricted writable paths
* resource limits
* appropriate system-call restrictions

Do not apply systemd restrictions that break required networking functionality without testing.

## SSH

SSH must:

* use key-based authentication where possible
* disable password authentication where appropriate
* disable root login
* use a non-default administrative policy
* be restricted to trusted networks where possible

## Network exposure

Expose only required ports.

The control panel/API must not be unnecessarily exposed to the WAN.

Management services must be restricted to trusted sources.

## Secrets

Never store plaintext:

* passwords
* private keys
* API secrets
* certificates containing private keys

Do not commit secrets.

Use appropriate filesystem permissions.

## Filesystem

Protect:

* configuration
* model files
* certificates
* private keys
* logs
* firewall state

Only required users/services should have write access.

## Updates

Document secure update procedures for:

* Raspberry Pi OS
* Python dependencies
* pirewall
* ML artifacts

## Resource exhaustion

Protect against:

* flow-table exhaustion
* event-queue exhaustion
* API abuse
* excessive rule creation
* excessive logging
* CPU exhaustion
* memory exhaustion

The Pi must remain operational under malicious traffic.

---

# 28. API

Use FastAPI.

Example endpoints:

```text
GET  /api/v1/health
GET  /api/v1/status

GET  /api/v1/flows
GET  /api/v1/detections
GET  /api/v1/threats
GET  /api/v1/decisions

GET  /api/v1/rules
GET  /api/v1/events
GET  /api/v1/models

POST /api/v1/rules/{id}/disable
POST /api/v1/rules/{id}/remove
```

Only expose implemented functionality.

Never expose arbitrary command execution.

---

# 29. API SECURITY

The API is security-sensitive.

Use:

* username/password authentication
* securely hashed passwords
* certificate-based security
* TLS
* IP restrictions
* authorization checks
* secure session/token handling

Only one administrator role is required.

Do not implement unnecessary RBAC.

When administrative access is exposed beyond the local network, restrict it to the configured Admin PC IP.

If the Admin PC IP changes, clearly report the configuration problem through the control panel.

---

# 30. CONTROL PANEL

The Pi has a **control panel**, not a dashboard.

Use:

* HTML
* CSS
* minimal JavaScript

Do not use a large frontend framework.

The control panel should show:

## System

* pirewall status
* uptime
* CPU
* memory
* packet rate
* active flows
* firewall status
* API status
* ML status

## Threats

* current threat level
* recent detections
* known attack detections
* anomalies
* threat assessments

## Firewall

* active rules
* adaptive rules
* rule status
* expiration
* reason
* recent changes

## Events

* detections
* blocks
* rule creation
* rejected rules
* rule expiration
* system errors
* model errors
* firewall errors
* authentication failures

## ML

* model versions
* feature schema version
* inference count
* inference latency
* detection statistics

The control panel must not become a privileged execution interface.

---

# 31. SECURITY EVENTS

Create a strongly typed `SecurityEvent`.

Event types may include:

```text
THREAT_DETECTED
FIREWALL_BLOCK
FIREWALL_ALLOW
RULE_CREATED
RULE_DEPLOYED
RULE_REJECTED
RULE_EXPIRED
MODEL_ERROR
CAPTURE_ERROR
FLOW_ERROR
FIREWALL_ERROR
AUTHENTICATION_FAILURE
SYSTEM_WARNING
```

Include where appropriate:

* timestamp
* severity
* event type
* subsystem
* source
* destination
* protocol
* flow ID
* threat score
* decision
* rule ID
* reason
* model version

Do not include unnecessary sensitive information.

---

# 32. WAZUH

The Admin PC runs Wazuh.

Forward important events from pirewall to the Admin PC.

Do not build a second SIEM.

Events should be structured and useful for correlation.

---

# 33. NETDATA

The Admin PC runs Netdata.

Expose useful operational metrics:

* CPU
* memory
* packet rate
* packet drops
* active flows
* flow creation
* flow expiration
* inference count
* inference latency
* detection count
* block count
* rule count
* rule rejection count
* API health
* capture health
* firewall health

---

# 34. ATTACK LAB

The system may be tested using:

* Kali Linux
* Ubuntu
* Linux Mint
* Windows
* Raspberry Pi
* Admin PC

Attack scenarios:

* XSS
* DNS spoofing
* ARP spoofing/MITM
* SYN flood
* port scanning
* SQL injection
* SSH brute force
* reverse shell
* DoS

Testing must occur only in an authorized laboratory environment.

Flow-based detection limitations must be documented.

Strongly observable:

* SYN floods
* port scanning
* brute-force connection patterns
* connection floods
* DoS patterns
* abnormal traffic rates
* unusual communication patterns

Potentially limited without payload inspection:

* XSS
* SQL injection
* reverse-shell payload contents

Do not claim payload-level detection from flow metadata alone.

---

# 35. REPOSITORY STRUCTURE

Use a single monorepo.

```text
pirewall/
│
├── README.md
├── pyproject.toml
├── uv.lock
├── .gitignore
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CODING_STANDARDS.md
│   ├── DEVELOPMENT_WORKFLOW.md
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   ├── API.md
│   ├── ML_PIPELINE.md
│   ├── FEATURE_SCHEMA.md
│   ├── FIREWALL.md
│   └── TESTING.md
│
├── config/
│   └── default_config.toml
│
├── pirewall/
│   ├── core/
│   │   ├── models/
│   │   ├── enums.py
│   │   └── exceptions.py
│   │
│   ├── capture/
│   │   ├── interfaces.py
│   │   ├── af_packet.py
│   │   └── parser.py
│   │
│   ├── flow/
│   │   ├── aggregator.py
│   │   ├── state.py
│   │   ├── key.py
│   │   └── timeout.py
│   │
│   ├── features/
│   │   ├── extractor.py
│   │   └── schema.py
│   │
│   ├── detection/
│   │   ├── known_attack.py
│   │   ├── anomaly.py
│   │   └── behavior.py
│   │
│   ├── engine/
│   │   ├── threat.py
│   │   ├── scoring.py
│   │   └── decision.py
│   │
│   ├── firewall/
│   │   ├── interface.py
│   │   ├── rules.py
│   │   ├── generator.py
│   │   ├── validator.py
│   │   ├── manager.py
│   │   └── backend/
│   │       └── nftables.py
│   │
│   ├── api/
│   │   ├── app.py
│   │   ├── auth.py
│   │   ├── schemas.py
│   │   └── routes/
│   │
│   ├── web/
│   │   ├── templates/
│   │   └── static/
│   │
│   ├── integration/
│   │   ├── wazuh.py
│   │   └── netdata.py
│   │
│   ├── ml/
│   │   ├── preprocessing/
│   │   │   ├── cicids_adapter.py
│   │   │   └── unsw_adapter.py
│   │   ├── training/
│   │   ├── inference/
│   │   └── artifacts/
│   │
│   └── main.py
│
├── scripts/
│   ├── train/
│   ├── deployment/
│   └── diagnostics/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── ml/
│   └── system/
│
└── deploy/
    ├── systemd/
    ├── firewall/
    ├── network/
    └── certificates/
```

Adjust the structure only when technically necessary.

Preserve architectural separation.

---

# 36. TECHNOLOGY STACK

Use:

* Python 3.12+
* uv
* Pydantic v2
* FastAPI
* Pytest
* Ruff
* LightGBM
* scikit-learn
* strict static type checking

Minimize dependencies.

Do not add dependencies without a technical reason.

---

# 37. CONFIGURATION

Use TOML.

Configuration must cover:

```text
network
capture
flow
features
detection
ml
threat
firewall
api
authentication
admin
logging
integration
security
```

Include where required:

* WAN interface
* LAN interface
* protected network
* Admin PC IP
* upstream gateway
* flow timeouts
* flow limits
* detection thresholds
* threat thresholds
* model paths
* firewall configuration
* API configuration
* certificates
* Wazuh integration
* logging
* resource limits

Never hard-code credentials or environment-specific interfaces.

---

# 38. LOGGING

Use structured logging.

Include where useful:

* timestamp
* severity
* subsystem
* event type
* flow ID
* source
* destination
* decision
* rule ID
* reason

Never log:

* passwords
* private keys
* authentication secrets

Protect log files with appropriate permissions.

Prevent unbounded log growth.

---

# 39. TESTING

Hardware-dependent components must have interfaces and test implementations.

Example:

```text
PacketCapture
    |
    +-- AF_PACKET
    |
    +-- FakePacketCapture
```

```text
FirewallBackend
    |
    +-- nftables
    |
    +-- FakeFirewallBackend
```

## Unit tests

Test:

* domain models
* validation
* packet parsing
* flow keys
* aggregation
* bidirectional flows
* timeouts
* feature extraction
* dataset adapters
* model metadata
* inference
* behavioral analysis
* threat scoring
* rule generation
* rule validation
* authentication
* configuration

## Integration tests

Test:

```text
Packet
  |
  v
Flow
  |
  v
FeatureVector
  |
  v
ML Evidence
  |
  v
Behavior
  |
  v
Threat Assessment
  |
  v
Firewall Decision
```

and:

```text
Threat Assessment
       |
       v
Candidate Rule
       |
       v
Validation
       |
       v
Firewall Backend
```

## Security tests

Test:

* malformed packets
* truncated packets
* invalid IPs
* invalid CIDRs
* invalid ports
* malformed configuration
* unauthorized API requests
* authentication failures
* certificate failures
* rule injection
* command injection
* overly broad rules
* duplicate rules
* conflicting rules
* Admin PC lockout
* firewall failure
* resource exhaustion

---

# 40. PERFORMANCE

Measure:

* packet throughput
* packet-drop rate
* flow latency
* feature-extraction latency
* inference latency
* threat-assessment latency
* rule-deployment latency
* CPU usage
* memory usage

Profile before optimizing.

Keep runtime resource usage bounded.

---

# 41. OBSERVABILITY

Expose enough information to determine:

* packet-capture health
* packet rate
* packet drops
* active flows
* flow creation/expiration
* detection count
* current threat level
* firewall decisions
* active rules
* rejected rules
* model versions
* inference latency
* Wazuh status
* API status
* firewall status
* system health

---

# 42. STARTUP

Use a deterministic startup sequence:

```text
Start
  |
  v
Load Configuration
  |
  v
Validate Configuration
  |
  v
Initialize Logging
  |
  v
Load ML Artifacts
  |
  v
Validate Model / Feature Compatibility
  |
  v
Validate Network Configuration
  |
  v
Initialize Firewall Backend
  |
  v
Initialize Flow Engine
  |
  v
Initialize Packet Capture
  |
  v
Initialize Feature Engine
  |
  v
Initialize Detection Engine
  |
  v
Initialize Threat Engine
  |
  v
Initialize API
  |
  v
Initialize Integrations
  |
  v
Health Checks
  |
  v
RUNNING
```

Critical failures must prevent unsafe startup.

---

# 43. SHUTDOWN

On shutdown:

* stop packet capture
* stop new flow creation
* process required pending state
* stop inference workers
* stop behavioral workers
* close resources
* stop API
* preserve safe firewall state
* record shutdown event

---

# 44. ERROR HANDLING

Use explicit exceptions such as:

```text
ConfigurationError
CaptureError
PacketParseError
FlowError
FeatureExtractionError
ModelLoadError
ModelInferenceError
ThreatAssessmentError
FirewallError
RuleValidationError
AuthenticationError
IntegrationError
```

Do not silently ignore exceptions.

---

# 45. PRIVILEGE SEPARATION

Privileged operations must be isolated where possible.

Use Linux capabilities and dedicated service accounts where appropriate.

Document required privileges.

The API/control-panel process must not receive unnecessary privileges.

A compromised control panel must not automatically provide unrestricted root access to the Pi.

---

# 46. NO FAKE IMPLEMENTATION

Do not fake core functionality.

Do not hard-code fake ML scores.

Do not claim a firewall rule was deployed when it was not.

Do not fabricate metrics or attack-detection results.

Clearly distinguish:

```text
Implemented
Tested
Mocked
Environment-dependent
Not yet validated
```

---

# 47. DEVELOPMENT WORKFLOW

For each subsystem:

1. Inspect existing code.
2. Identify its contract.
3. Implement or fix it.
4. Add tests.
5. Run tests.
6. Run Ruff.
7. Run strict type checking.
8. Fix issues.
9. Update documentation.
10. Run integration tests.

Avoid:

* giant files
* giant classes
* circular dependencies
* hidden global state
* duplicated logic
* magic constants
* arbitrary dictionaries
* scattered shell commands

---

# 48. IMPLEMENTATION ORDER

Implement in this order:

```text
1. Repository foundation
2. Configuration
3. Core domain models
4. Type-safe interfaces
5. Packet representation
6. Packet capture
7. Packet parsing
8. Flow aggregation
9. Canonical feature schema
10. Feature extraction
11. Dataset adapters
12. ML preprocessing
13. ML training
14. Model artifacts
15. ML inference
16. Behavioral analysis
17. Threat assessment
18. Firewall decision engine
19. Candidate rule generation
20. Rule validation
21. nftables backend
22. Adaptive enforcement
23. Security events
24. API
25. Authentication
26. Control panel
27. Wazuh integration
28. Metrics/Netdata integration
29. Raspberry Pi hardening
30. Network deployment
31. systemd deployment
32. Security testing
33. Integration testing
34. Documentation
35. Final validation
```

Do not implement adaptive enforcement before rule validation.

Do not implement runtime ML inference before the feature schema is stable.

---

# 49. EXISTING REPOSITORY

Before changing an existing repository:

1. Inspect the complete repository structure.
2. Read existing documentation.
3. Inspect `pyproject.toml`.
4. Inspect configuration.
5. Inspect domain models.
6. Inspect networking code.
7. Inspect ML code.
8. Inspect firewall code.
9. Inspect API/control-panel code.
10. Inspect tests.
11. Identify implemented, incomplete, and broken components.

Preserve correct existing work.

Do not blindly rewrite working components.

---

# 50. ACCEPTANCE CRITERIA

The completed system must provide:

## Network

* packet capture
* packet parsing
* flow aggregation
* bidirectional flows
* flow timeouts
* bounded state
* canonical Flow

## Features

* canonical schema
* deterministic extraction
* training/runtime compatibility

## ML

* CICIDS2017 adapter
* UNSW-NB15 adapter
* preprocessing
* LightGBM
* Isolation Forest
* training pipeline
* model artifacts
* metadata
* compatibility validation

## Detection

* known-attack evidence
* anomaly evidence
* behavioral analysis
* threat scoring
* explainable assessments

## Firewall

* explicit decisions
* structured rules
* candidate generation
* validation
* conflict detection
* duplicate detection
* safety checks
* expiration
* enforcement
* audit trail

## Gateway

* WAN/LAN configuration
* forwarding
* routing
* firewall forwarding
* NAT where required
* protected network

## API

* FastAPI
* authentication
* TLS
* certificate support
* Admin PC restriction
* safe administrative operations

## Control Panel

* system health
* network statistics
* threats
* detections
* firewall rules
* events
* ML status

## Integration

* Wazuh
* Netdata/metrics
* Admin PC communication

## Raspberry Pi Security

* least privilege
* service isolation
* secure systemd configuration
* SSH hardening
* restricted network exposure
* secret protection
* filesystem permissions
* resource limits
* secure firewall management
* secure update procedure

## Testing

* unit tests
* integration tests
* ML tests
* security tests
* failure tests
* mocked hardware tests
* strict type checking

## Deployment

* Raspberry Pi installation
* network configuration
* IP forwarding
* firewall configuration
* permissions/capabilities
* systemd
* certificates
* Admin PC configuration

## Documentation

* README
* architecture
* feature schema
* ML pipeline
* firewall
* security
* deployment
* testing
* Raspberry Pi hardening

---

# 51. FINAL ARCHITECTURAL REQUIREMENT

The complete system must preserve this separation:

```text
                 NETWORK
                    |
                    v
             PACKET CAPTURE
                    |
                    v
             FLOW AGGREGATION
                    |
                    v
            FEATURE EXTRACTION
                    |
          +---------+---------+
          |                   |
          v                   v
       LightGBM        Isolation Forest
          |                   |
          +---------+---------+
                    |
                    v
             BEHAVIOR ANALYSIS
                    |
                    v
             THREAT ASSESSMENT
                    |
                    v
             FIREWALL DECISION
                    |
                    v
             CANDIDATE RULE
                    |
                    v
             RULE VALIDATION
                    |
                    v
             FIREWALL BACKEND
                    |
                    v
               NFTABLES
                    |
                    v
             NETWORK TRAFFIC
```

Security events flow separately:

```text
Threat / Firewall / System Events
              |
       +------+------+
       |             |
       v             v
     Wazuh      Control Panel
```

The Raspberry Pi must be secured as part of the firewall architecture.

Implement **pirewall** as a real deployable system, not a simulated architecture.

Priorities:

1. Security
2. Correctness
3. Type safety
4. Reliability
5. Architectural separation
6. Testability
7. Resource efficiency
8. Maintainability
9. Performance
10. Documentation
