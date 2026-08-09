# Pirewall Constitution

Version: 1.0
Status: Active

---

# Purpose

Pirewall is an AI-powered adaptive firewall designed to protect edge networks using a Raspberry Pi.

The project combines machine learning, behavioral analysis, deterministic rule evaluation, and cloud-assisted policy recommendations while maintaining low latency and deterministic enforcement.

The Raspberry Pi is always the primary enforcement point.

---

# Vision

The project aims to build an explainable, modular, maintainable firewall that can detect both known and previously unseen threats while remaining lightweight enough to operate continuously on a Raspberry Pi.

Machine learning assists security decisions.

Machine learning never replaces deterministic enforcement.

---

# Repository Architecture

The project consists of four repositories.

```
pirewall
pirewall-cloud
pirewall-dash
pirewall-shared
```

Each repository owns a single responsibility.

Repositories must never duplicate functionality.

---

# Repository Responsibilities

## pirewall

Runs on Raspberry Pi.

Responsible for:

- Packet capture
- Flow generation
- Feature extraction
- ML inference
- Behavior analysis
- Threat scoring
- Rule validation
- Firewall enforcement
- Cloud communication

---

## pirewall-cloud

Runs on a server.

Responsible for:

- API
- Authentication
- Historical storage
- Policy recommendation
- Notifications
- Dashboard backend
- Model distribution

---

## pirewall-dash

Responsible only for visualization and administration.

Contains no business logic.

Communicates only with the cloud.

---

## pirewall-shared

Contains:

- Domain models
- Shared schemas
- Events
- Enums
- Interfaces
- Constants
- Validation
- Serialization

Contains no networking or business logic.

---

# Core Architecture

Pirewall follows a modular monolith architecture on the Raspberry Pi.

Internal modules communicate through interfaces and lightweight events.

No microservices run on the Raspberry Pi.

The cloud may use Docker.

The Raspberry Pi shall not.

---

# Execution Model

Latency-critical pipeline:

Packet
↓
Packet Capture
↓
Flow Generator
↓
Flow
↓
Feature Extraction
↓
Feature Vector
↓
──────── Parallel Inference ────────
│ LightGBM
│ Isolation Forest
│ Behavior Engine
────────────────────────────────────
↓
Assessment Engine
↓
Threat Assessment
↓
Decision Engine
↓
Firewall Decision
↓
Rule Compiler
↓
Rule Validator
↓
Firewall Manager
↓
nftables

Background work includes:

- Logging
- Metrics
- Dashboard updates
- Cloud synchronization
- Notifications

Background Services

- Cloud Sync
- Dashboard Upload
- Metrics
- Log Upload
- Model Update

Background failures must never interrupt packet processing.

---

# Detection Philosophy

Three independent engines contribute evidence.

LightGBM

↓

Known attack confidence

Isolation Forest

↓

Anomaly confidence

Behavior Engine

↓

Behavior confidence

The Threat Scoring Engine combines these signals into one Threat Assessment.

No individual engine may directly block traffic.

---

# Rule Philosophy

The cloud never sends executable firewall commands.

Instead, it sends Policy Recommendations.

The Raspberry Pi validates every recommendation.

Validated recommendations are compiled into nftables rules using predefined templates.

The Raspberry Pi is always the final authority.

---

# Offline Operation

Loss of cloud connectivity must not disable:

- Packet capture
- ML inference
- Behavior analysis
- Existing firewall rules
- Temporary mitigation

Cloud functionality resumes automatically when connectivity returns.

---

# Domain Model Rules

Raw packets exist only inside packet capture.

Every downstream module consumes Flow Objects.

Flow Objects are immutable.

Threat Evidence is immutable.

Threat Assessments are immutable.

Every shared domain model exists only inside pirewall-shared.

---

# Module Principles

Every module has exactly one responsibility.

Modules communicate only through public interfaces.

Modules may not access another module's internal implementation.

Circular dependencies are forbidden.

Global mutable state is forbidden.

---

# Dependency Rules

Allowed:

Flow → Features

Features → Inference

Inference → Threat

Threat → Firewall

Forbidden:

Firewall → Capture

Firewall → Features

Threat → Capture

Cloud → Internal Pi Modules

Dashboard → Pi

---

# Configuration

Configuration uses YAML.

Secrets use .env.

Configuration shall never be hardcoded.

---

# Logging

Logging is asynchronous.

Logging must never block packet processing.

Every log contains:

- Timestamp
- Component
- Severity
- Correlation ID
- Message

---

# Security

Zero Trust.

Every external input is validated.

Cloud recommendations are never automatically trusted.

No AI-generated shell commands.

Firewall rules are created only from approved templates.

Every deployed rule supports rollback.

---

# Testing

Every public component requires tests.

Every bug requires a regression test.

Replay testing using PCAP files is mandatory.

---

# Coding Standards

Python 3.13+

Type hints required.

Pydantic v2 for shared models.

PEP 8 compliance.

Composition over inheritance.

Dependency injection preferred.

No wildcard imports.

Document all public APIs.

---

# Performance Goals

The Raspberry Pi should remain responsive under expected laboratory traffic.

Critical-path latency should remain as low as practical.

Background processing must never degrade enforcement performance.

---

# AI Development Rules

Every AI assistant working on this repository must:

- Read this Constitution before making changes.
- Preserve repository boundaries.
- Preserve module boundaries.
- Avoid architectural changes.
- Ask questions when requirements are ambiguous.

The AI must never:

- Invent new architecture.
- Duplicate shared models.
- Introduce circular dependencies.
- Hardcode configuration.
- Hardcode secrets.
- Generate placeholder security implementations without clearly marking them.

---

# System Invariants

These rules must never be violated.

- The Raspberry Pi is the Policy Enforcement Point.
- The cloud is advisory.
- Raw packets never leave packet capture.
- Every downstream module consumes Flow Objects.
- ML never directly deploys firewall rules.
- Every firewall rule is validated.
- Every rule supports rollback.
- Background tasks never block packet forwarding.
- Shared contracts exist only in pirewall-shared.

---

# Definition of Done

A feature is complete only when:

- Architecture complies with this Constitution.
- Documentation is updated.
- Tests pass.
- Logging exists.
- Configuration is externalized.
- Security implications are considered.
- No architectural debt is introduced.

# Cloud Responsibilities

- Dashboard
- Historical Storage
- Policy Engine
- Model Retraining
- Threat Intelligence
- OTA Model Updates

Never:

- Packet Processing
- Packet Capture
- Firewall Enforcement
- Rule Deployment
