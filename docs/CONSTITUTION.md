# Pirewall Constitution
**Version:** 1.0.0
**Status:** Draft (Architecture Frozen)
**Authors:** Ashmit Jain (System Architect), ChatGPT (Architecture Advisor)
# Table of Contents
```text
1. Vision & Philosophy
2. Project Scope
3. Non-Goals
4. Core Principles
5. High-Level Architecture
6. Repository Architecture
7. Canonical Data Model
8. System Execution Model
9. Critical Path
10. Background Services
11. ML Architecture
12. Behavior Analysis Engine
13. Threat Scoring Engine
14. Policy Recommendation Engine
15. Rule Validation & Deployment
16. Repository Specifications
17. Module Dependency Rules
18. Threading Model
19. Event System
20. Configuration Standards
21. Error Handling
22. Logging Standards
23. Testing Strategy
24. Performance Targets
25. Security Principles
26. AI Development Rules
27. Future Expansion
```
---
# 1. Vision & Philosophy
## 1.1 Vision
Pirewall is an intelligent, adaptive, AI-assisted firewall designed specifically for deployment on resource-constrained edge devices. The system combines supervised machine learning, unsupervised anomaly detection, deterministic behavioral analysis, and policy-based firewall management to provide protection against both known and previously unseen network threats.

Unlike traditional firewalls that rely solely on static signatures or manually written rules, Pirewall continuously evaluates network traffic using multiple independent sources of evidence while maintaining deterministic and explainable enforcement decisions.

The Raspberry Pi serves as an autonomous edge security appliance capable of continuing protection even when disconnected from cloud services.

---

## 1.2 Design Philosophy

Every architectural decision in Pirewall follows five principles.

### Principle 1 — Edge First

The Raspberry Pi is the primary enforcement point.

The cloud enhances the firewall.

The cloud never replaces the firewall.

Loss of connectivity must never disable protection.

---

### Principle 2 — Deterministic Enforcement

Machine learning provides evidence.

Machine learning never directly modifies firewall rules.

Every enforcement action must be explainable and reproducible.

---

### Principle 3 — Separation of Responsibilities

Every module has one responsibility.

Modules communicate through defined interfaces.

Modules never perform responsibilities belonging to another subsystem.

---

### Principle 4 — Performance Before Complexity

Pirewall prioritizes:

* predictable latency
* low memory usage
* deterministic execution

over architectural trends.

The Raspberry Pi intentionally runs a modular monolith rather than a microservice architecture.

---

### Principle 5 — Extensibility Without Refactoring

Future functionality should be added by introducing new modules or subscribing to existing events rather than modifying established modules.

Existing interfaces should remain stable whenever possible.

---

# 2. Project Scope

Pirewall is designed to:

* Operate as the default gateway for a protected network.
* Inspect flow-based network traffic.
* Detect known attacks using supervised machine learning.
* Detect unknown attacks using anomaly detection.
* Maintain behavioral state for hosts.
* Fuse evidence into a single threat score.
* Apply temporary mitigation locally.
* Request policy recommendations from the cloud.
* Validate all received policies before enforcement.
* Manage firewall rules using `nftables`.
* Provide administrators with a monitoring dashboard.
* Continue operating without cloud connectivity.

---

# 3. Non-Goals

The following capabilities are intentionally outside the scope of Version 1:

* Deep packet inspection of encrypted payloads.
* Full IDS signature engine comparable to Suricata or Snort.
* Distributed clustering of multiple edge firewalls.
* Automatic machine learning retraining on the Raspberry Pi.
* Autonomous generation of arbitrary firewall commands.
* Full replacement for enterprise SIEM platforms.
* Inline TLS interception.
* Stateful Layer 7 application proxying.

---

# 4. Core Principles

## Canonical Data Model

The Flow Object is the single canonical data model for the system.

No module outside Packet Capture and Flow Generation may operate directly on raw packets.

Every downstream component consumes Flow Objects exclusively.

---

## Explainability

Every enforcement decision must be traceable to explicit evidence.

A decision should always be explainable through:

* Known attack confidence
* Anomaly score
* Behavior score
* Applied policy
* Validation outcome

---

## Cloud Trust Model

The cloud is advisory.

The Raspberry Pi is authoritative.

The Pi validates every policy before deployment.

---

## Offline Operation

Loss of cloud connectivity must not prevent:

* packet inspection
* ML inference
* behavior analysis
* temporary mitigation
* enforcement of existing rules

Cloud synchronization resumes automatically when connectivity returns.

---

# 5. High-Level Architecture

```text
                           Internet
                               │
                               ▼
                     Raspberry Pi Gateway
                               │
       ┌────────────────────────────────────────┐
       │            Critical Path               │
       │                                        │
       │ Packet Capture                         │
       │      ↓                                 │
       │ Flow Generation                        │
       │      ↓                                 │
       │ Feature Extraction                     │
       │      ↓                                 │
       │ Inference Worker Pool                  │
       │      ├── LightGBM                      │
       │      ├── Isolation Forest              │
       │      └── Behavior Engine               │
       │              ↓                         │
       │ Threat Scoring Engine                  │
       │              ↓                         │
       │ Firewall Decision                      │
       │              ↓                         │
       │ nftables                               │
       └────────────────────────────────────────┘
                               │
                               ▼
                    Background Event Bus
                               │
      ┌─────────────┬─────────────┬──────────────┐
      ▼             ▼             ▼              ▼
    Logging     Cloud Sync     Metrics      Dashboard API
```
# 6. Repository Architecture

The Pirewall project is divided into four repositories.

Each repository has a clearly defined purpose.

Repositories may communicate only through published interfaces and shared contracts.

No repository may duplicate functionality belonging to another repository.

---

## Repository Overview

```text
                    +----------------------+
                    |  pirewall-shared     |
                    |  Shared Contracts    |
                    +----------+-----------+
                               |
                 +-------------+-------------+
                 |                           |
                 |                           |
        +--------+--------+          +-------+--------+
        | pirewall-pi     |          | pirewall-cloud |
        | Edge Firewall   |          | Cloud Backend  |
        +--------+--------+          +-------+--------+
                 |                           |
                 +-------------+-------------+
                               |
                               |
                     +---------+---------+
                     | pirewall-dash     |
                     | Admin Dashboard   |
                     +-------------------+
```

---

## Repository Responsibilities

### 6.1 `pirewall-shared`

Purpose:

Provide common data models, interfaces, schemas, enums, constants, and validation rules.

It is the single source of truth for shared objects.

### Responsibilities

* Flow model
* ThreatScore model
* BehaviorScore model
* FirewallRule model
* PolicyRecommendation model
* API request/response schemas
* Event definitions
* Enums
* Shared constants
* Validation logic
* Serialization

### Must NOT contain

* Packet capture
* Networking
* HTTP servers
* React code
* Database access
* ML models
* Firewall logic
* Cloud logic

---

### 6.2 `pirewall-pi`

Purpose:

Real-time inspection and enforcement.

Runs exclusively on Raspberry Pi.

### Responsibilities

* Packet capture
* Flow generation
* Feature extraction
* ML inference
* Behavior engine
* Threat scoring
* Rule validation
* Firewall management
* Local storage
* Cloud communication
* Event publishing

### Must NOT contain

* Dashboard UI
* Database server
* Model training
* Cloud analytics
* Long-term reporting

---

### 6.3 `pirewall-cloud`

Purpose:

Central management platform.

Runs on a server.

### Responsibilities

* API
* Authentication
* Historical storage
* Policy recommendation
* Rule lifecycle management
* Dashboard backend
* Notifications
* Model distribution

### Must NOT

* Capture packets
* Execute firewall rules
* Assume authority over Pi
* Directly modify nftables

---

### 6.4 `pirewall-dash`

Purpose

Administrator interface.

### Responsibilities

* Visualization
* Authentication
* Rule management UI
* Threat timeline
* Device overview
* Reports
* Statistics

### Must NOT

* Contain business logic
* Generate firewall rules
* Store security decisions
* Communicate directly with Pi

Dashboard communicates only with Cloud APIs.

---

# 7. Dependency Rules

Dependencies are directional.

Circular dependencies are forbidden.

---

## Repository Dependency Graph

```text
pirewall-shared

↑

├───────────────┐

│               │

│               │

pirewall-pi   pirewall-cloud

        ↑

        │

pirewall-dashboard
```

Allowed:

```
Pi → Shared

Cloud → Shared

Dashboard → Cloud

Dashboard → Shared
```

Forbidden:

```
Shared → Pi

Shared → Cloud

Pi → Dashboard

Dashboard → Pi

Cloud → Pi
```

The cloud communicates with the Pi only through APIs.

---

# 8. Module Architecture (Pi)

The Pi application is a **modular monolith**.

Internally it consists of independent modules.

Each module owns one responsibility.

Modules communicate through interfaces and the internal event bus.

---

## Module Overview

```text
Packet Capture

↓

Flow Generator

↓

Feature Extraction

↓

Inference Queue

↓

Inference Worker Pool

↓

Threat Scoring

↓

Firewall Manager

↓

Cloud Client
```

Parallel background services:

```
Logger

Metrics

Storage

Dashboard Sync

Cloud Sync
```

---

## Internal Modules

```
capture/

flow/

features/

inference/

behavior/

threat/

firewall/

communication/

events/

storage/

config/
```

No module may contain logic belonging to another module.

---

# 9. Module Dependency Matrix

This matrix defines every legal dependency.

| Module        | Allowed Dependencies        |
| ------------- | --------------------------- |
| capture       | events, shared              |
| flow          | capture, events, shared     |
| features      | flow, shared                |
| inference     | features, shared            |
| behavior      | shared, events              |
| threat        | inference, behavior, shared |
| firewall      | threat, shared              |
| communication | shared                      |
| storage       | shared                      |
| config        | none                        |
| events        | shared                      |

Forbidden dependencies are considered architecture violations.

---

# 10. Single Responsibility Principle

Every module has one responsibility.

Examples:

Packet Capture

Responsible for capturing packets.

Nothing else.

Flow Generator

Responsible for creating Flow Objects.

Nothing else.

Threat Scoring

Responsible for evidence fusion.

Nothing else.

Firewall Manager

Responsible for translating validated policies into nftables operations.

Nothing else.

---

# 11. Communication Rules

Modules do not communicate by directly manipulating another module's internal state.

Allowed:

```
Public interfaces

Events

Shared models
```

Forbidden:

```
Importing another module's private implementation

Modifying another module's internal objects

Circular callbacks

Global mutable state
```

---

# 12. AI Development Rules

These rules apply to **every AI-generated contribution**.

The AI must never:

* Invent architecture.
* Merge unrelated modules.
* Duplicate shared models.
* Introduce circular dependencies.
* Bypass interfaces.
* Generate placeholder security code without marking it clearly.
* Hardcode secrets.
* Hardcode IP addresses.
* Assume network topology not defined in the constitution.

The AI must:

* Preserve repository boundaries.
* Preserve module boundaries.
* Prefer composition over inheritance.
* Prefer dependency injection over global state.
* Write documentation before implementation.
* Generate tests for every public component.
* Keep modules cohesive and loosely coupled.

---

# 13. Canonical Data Model

## Philosophy

The entire Pirewall ecosystem communicates using **shared domain models**.

These models are defined **once** in `pirewall-shared`.

No repository may redefine or extend these models in incompatible ways.

They represent the language of the entire system.

---

## Rule 13.1

> Every component after the Flow Generator consumes Flow Objects.

No module outside `capture/` and `flow/` may operate on raw packets.

```
Packet
   │
   ▼
Capture
   │
   ▼
Flow Generator
   │
   ▼
Flow Object
   │
   ├── Feature Extraction
   ├── ML Inference
   ├── Behavior Engine
   ├── Threat Scoring
   ├── Logging
   ├── Cloud
   └── Dashboard
```

---

# 14. Core Domain Models

These models form the shared language between all repositories.

---

## 14.1 Flow

Represents a completed network communication suitable for analysis.

The Flow is immutable once created.

It contains:

* Unique Flow ID
* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol
* Flow Start Time
* Flow End Time
* Duration
* Packet Count
* Byte Count
* TCP Flag Summary
* Direction
* Feature Vector
* Metadata

The Flow never contains ML results.

---

## 14.2 Threat Evidence

Each detection engine produces evidence, not decisions.

Examples:

```
LightGBM Evidence

Known Attack Probability

Attack Family

Confidence
```

```
Isolation Forest Evidence

Anomaly Score

Normalized Score

Confidence
```

```
Behavior Evidence

Behavior Score

Triggered Rules

Host Reputation
```

Each engine is independent.

---

## 14.3 Threat Assessment

Generated only by the Threat Scoring Engine.

Contains:

* Final Threat Score
* Confidence
* Risk Level
* Recommended Action
* Explanation
* Supporting Evidence

Only one Threat Assessment exists for each Flow.

---

## 14.4 Firewall Rule

Represents an abstract policy.

Not an nftables command.

Example concept:

```
Action:
BLOCK_IP

Target:
192.168.1.20

Duration:
600 seconds

Reason:
Repeated SSH Brute Force
```

The Pi later compiles this into nftables.

---

## 14.5 Policy Recommendation

Generated only by the cloud.

Contains:

* Recommendation ID
* Trigger
* Supporting Evidence
* Proposed Rule
* Confidence
* Expiration
* Priority

The Pi never executes this directly.

---

# 15. Domain Ownership

Every object has exactly one owner.

| Object                | Owner                 |
| --------------------- | --------------------- |
| Flow                  | Flow Generator        |
| Threat Evidence       | Detection Engines     |
| Threat Assessment     | Threat Scoring Engine |
| Firewall Rule         | Rule Engine           |
| Policy Recommendation | Cloud                 |
| Host State            | Behavior Engine       |

Ownership cannot change.

---

# 16. Immutability Rules

Once created:

Flow Objects cannot change.

Threat Evidence cannot change.

Threat Assessments cannot change.

Instead:

New versions are produced.

Example:

```
Flow

↓

Threat Assessment V1

↓

Threat Assessment V2

↓

Threat Assessment V3
```

Historical state is preserved.

This greatly simplifies debugging.

---

# 17. Event System

The internal event system exists only to notify background services.

It is **not** used to execute latency-critical logic.

---

## Event Philosophy

Events describe something that has already happened.

Examples:

```
FlowCreated

ThreatCalculated

RuleValidated

RuleApplied

HostBlocked

CloudConnected

CloudDisconnected

PolicyReceived
```

Notice the past tense.

An event never means:

> "Go do this."

It means:

> "This already happened."

---

## Event Rules

Events are:

Immutable.

Timestamped.

Serializable.

Versioned.

Replayable.

---

## Event Consumers

Examples:

```
Logger

Metrics

Storage

Dashboard Sync

Cloud Sync

Audit Trail
```

Subscribers never modify the event.

---

# 18. Execution Model

Pirewall uses two execution paths.

---

## Critical Path

Latency-sensitive.

```
Packet

↓

Capture

↓

Flow

↓

Features

↓

Inference

↓

Threat Score

↓

Firewall Decision
```

No logging.

No cloud.

No disk writes.

No dashboard.

---

## Background Path

Everything else.

```
Event Bus

↓

Logger

↓

Cloud

↓

Metrics

↓

Dashboard

↓

Storage

↓

Notifications
```

Failure here must never interrupt packet processing.

---

# 19. Worker Architecture

Inference is isolated from packet capture.

```
Capture

↓

Flow Queue

↓

Inference Worker Pool

↓

Threat Queue

↓

Firewall
```

---

## Worker Pool

Configurable.

Default:

```
One Worker
```

Supported:

```
Two Workers
```

Additional workers require explicit configuration.

---

## Worker Responsibilities

Each worker performs:

* Feature normalization
* LightGBM inference
* Isolation Forest inference
* Behavior evaluation
* Threat evidence generation

Workers never update firewall rules.

---

# 20. Evidence Fusion

This chapter defines the core innovation of Pirewall.

No detection engine makes decisions.

Each engine contributes evidence.

```
               Flow
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
  LightGBM   Isolation   Behavior
                Forest
       │         │         │
       └─────────┼─────────┘
                 ▼
        Threat Scoring Engine
                 ▼
         Threat Assessment
```

The Threat Scoring Engine evaluates all evidence together.

No individual engine has authority.

---

# 21. Decision Philosophy

The firewall does not ask:

> "Is this malicious?"

Instead it asks:

> "Given all available evidence, what action minimizes risk while preserving legitimate traffic?"

That distinction is important.

The system is **risk-based**, not simply **signature-based**.

---

# At this point, our architecture is essentially frozen

We've now defined:

* The repositories.
* Their responsibilities.
* Module boundaries.
* Shared contracts.
* Execution model.
* Event model.
* Worker model.
* Threat fusion model.

These decisions are the hardest ones, and they're now documented.

---
This is where the Constitution starts becoming **a real engineering document** instead of just an architecture description.

Everything below is exactly the type of standards used on professional projects to keep a codebase maintainable for years.

---

# 22. Configuration Philosophy

Pirewall must be configurable without modifying source code.

All operational settings shall exist outside the application.

Configuration must be human-readable.

The preferred format is YAML.

Secrets must never be stored in YAML.

---

## Configuration Hierarchy

```text
config/

base.yaml

development.yaml

production.yaml

models.yaml

network.yaml

firewall.yaml

behavior.yaml

logging.yaml
```

---

## Environment Variables

Only secrets belong in `.env`

Examples:

```
DATABASE_URL

JWT_SECRET

API_KEY

CLOUD_TOKEN

PRIVATE_KEY
```

Never:

```
Threat Threshold

Packet Timeout

Worker Count

Model Paths
```

Those belong inside YAML.

---

# 23. Logging Standards

Logging is a background task.

Logging must never block packet processing.

---

## Every log entry must contain

Timestamp

Component

Event Type

Severity

Correlation ID

Message

Optional Metadata

Example

```
2027-03-14T14:03:11Z

ThreatEngine

INFO

FlowProcessed

FlowID=12345

ThreatScore=82
```

---

## Logging Levels

```
TRACE

DEBUG

INFO

WARNING

ERROR

CRITICAL
```

No custom levels.

---

# 24. Error Handling Philosophy

Errors must never be silently ignored.

Every exception must belong to one of four categories.

---

## Recoverable

Retry.

Continue.

Example:

Temporary cloud outage.

---

## Validation

Reject input.

Continue.

Example:

Malformed Policy Recommendation.

---

## Internal

Unexpected software error.

Log.

Raise alert.

Continue if safe.

---

## Fatal

Immediate shutdown.

Only used when system integrity cannot be guaranteed.

Example:

Corrupted configuration.

Missing ML models.

Firewall backend unavailable.

---

# 25. Security Principles

Every security decision follows Zero Trust.

No component is trusted simply because it is internal.

---

## Rule 1

Cloud recommendations are never trusted.

They must be validated.

---

## Rule 2

No component may execute shell commands created from AI output.

---

## Rule 3

Firewall rules are generated only from predefined templates.

Never arbitrary commands.

---

## Rule 4

Every policy must be validated against:

Supported action.

Supported target.

Conflicting rules.

Whitelist.

Expiration.

Priority.

Network safety.

---

## Rule 5

Every deployed rule must support rollback.

Rollback information must be stored before deployment.

---

# 26. Performance Targets

These are engineering goals rather than strict guarantees.

---

## Packet Capture

Packet loss should remain negligible under expected laboratory traffic.

---

## Flow Generation

Flow creation should complete with minimal buffering delay.

---

## Inference

Average inference latency per flow should remain in the low millisecond range under normal load.

---

## Memory

The Pi application should comfortably operate within the available memory of a Raspberry Pi 4 (4 GB), leaving headroom for the operating system and networking stack.

---

## Startup

The firewall service should become operational shortly after boot, with models loaded before traffic enforcement begins.

---

# 27. Testing Strategy

Every public module requires automated tests.

---

## Unit Tests

Every module.

Every public interface.

---

## Integration Tests

Flow Generation

Inference

Firewall

Cloud Communication

Rule Validation

---

## Replay Tests

Recorded PCAP files.

Expected Threat Scores.

Expected Firewall Decisions.

---

## Simulation Tests

Your lab attacks.

SSH Brute Force

Port Scan

SYN Flood

DNS Spoof

ARP Spoof

SQL Injection

Reverse Shell

XSS

---

## Regression Tests

Every bug fixed becomes a permanent automated test.

---

# 28. Documentation Standards

Every module contains:

README.md

Purpose

Responsibilities

Public Interfaces

Dependencies

Limitations

Future Improvements

---

Every public class contains documentation.

Every public method contains documentation.

---

# 29. Coding Standards

Python:

PEP8

Type hints everywhere.

Dataclasses or Pydantic where appropriate.

Avoid global mutable state.

Dependency injection preferred.

Composition preferred over inheritance.

No wildcard imports.

Explicit imports only.

---

# 30. Repository Standards

Every repository follows the same structure.

```
docs/

src/

tests/

config/

scripts/

README.md

LICENSE

.gitignore

CHANGELOG.md
```

---

# 31. Git Standards

Main branch

Always deployable.

Feature branches

One feature only.

Commits

Small.

Atomic.

Descriptive.

Examples

```
Add Flow Generator interface

Implement Threat Evidence model

Add Rule Validator tests
```

Never:

```
fix

changes

update

misc
```

---

# 32. Architecture Decision Records (ADR)

Every major architectural change requires an ADR.

Example

```
ADR-0001

Decision:

Modular Monolith

Status:

Accepted

Reason:

Reduced latency on Raspberry Pi
```

Future developers should understand **why** a decision exists, not just **what** the code does.

---

# 33. AI Development Rules

This section governs every AI-generated contribution.

Before generating code, the AI must:

1. Read the Constitution.
2. Identify affected modules.
3. Respect repository boundaries.
4. Respect dependency rules.
5. Avoid architectural changes.
6. Ask questions if requirements are ambiguous.

The AI must **never**:

* Invent new repositories.
* Introduce new top-level modules without approval.
* Duplicate shared models.
* Bypass interfaces.
* Modify another module's private implementation.
* Introduce circular dependencies.
* Hardcode secrets or configuration.
* Generate placeholder security logic without clearly marking it.

If a requested change conflicts with the Constitution, the AI should explain the conflict rather than silently changing the architecture.

---

# 34. Future Expansion

The architecture is intentionally designed to support future enhancements without major refactoring.

Potential additions include:

* Additional anomaly detection models.
* Threat intelligence feeds.
* Multiple Raspberry Pi nodes managed by one cloud instance.
* Centralized policy synchronization.
* IPv6 support.
* eBPF-based packet capture.
* Hardware acceleration on more powerful edge devices.
* Plugin-based detection modules.

These additions should integrate through existing interfaces rather than replacing core components.

---

# 35. Definition of Done

A feature is considered complete only when all of the following are satisfied:

* Architecture complies with the Constitution.
* Code is documented.
* Unit tests pass.
* Integration tests pass (where applicable).
* Public interfaces are stable.
* Configuration is externalized.
* Logging is implemented.
* Error handling is complete.
* Security implications have been considered.
* No new architectural debt has been introduced.

---

## "System Invariants"

These are **rules that must never be violated**, regardless of future changes.

Examples:

* The Raspberry Pi is always the **Policy Enforcement Point**.
* The cloud is always **advisory**, never authoritative.
* Raw packets never leave the Packet Capture/Flow Generation boundary.
* Every downstream component consumes **Flow Objects** only.
* No ML model directly creates or deploys firewall rules.
* Every firewall rule is validated before deployment.
* Every deployed rule can be rolled back.
* The critical path must never depend on cloud connectivity.
* Background tasks must never block packet forwarding.
* Shared domain models exist only in `pirewall-shared`.
* Repository and module boundaries are preserved unless an approved ADR explicitly changes them.

Those invariants become the "constitution above the constitution." They provide a simple checklist that you, reviewers, or future AI sessions can use to verify that the architecture remains true to its original design.
