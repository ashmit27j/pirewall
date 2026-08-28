"""Read-only endpoints (spec §28): status, capture statistics, flows, detections, threats,
decisions, rules, events, models."""

from fastapi import APIRouter

from pirewall.api.app import RpcClientDep
from pirewall.core.models.capture_stats import CaptureStatistics
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.detection_record import DetectionRecord
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.flow import Flow
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.core.models.rule import FirewallRule
from pirewall.core.models.status import StatusResult
from pirewall.core.models.threat import ThreatAssessment

router = APIRouter(prefix="/api/v1", tags=["read"])


@router.get("/status", response_model=StatusResult)
def get_status(rpc_client: RpcClientDep) -> StatusResult:
    return rpc_client.get_status()


@router.get("/capture-stats", response_model=CaptureStatistics | None)
def get_capture_stats(rpc_client: RpcClientDep) -> CaptureStatistics | None:
    """Current packet capture counters — the control panel's "network statistics" (spec §30).

    `null` means pirewall-core has not reported a reading yet (it publishes
    one per watchdog tick), which is distinct from "zero packets seen".
    """
    return rpc_client.get_capture_stats()


@router.get("/flows", response_model=list[Flow])
def list_flows(rpc_client: RpcClientDep) -> list[Flow]:
    return rpc_client.list_flows()


@router.get("/detections", response_model=list[DetectionRecord])
def list_detections(rpc_client: RpcClientDep) -> list[DetectionRecord]:
    return rpc_client.list_detections()


@router.get("/threats", response_model=list[ThreatAssessment])
def list_threats(rpc_client: RpcClientDep) -> list[ThreatAssessment]:
    return rpc_client.list_threats()


@router.get("/decisions", response_model=list[FirewallDecision])
def list_decisions(rpc_client: RpcClientDep) -> list[FirewallDecision]:
    return rpc_client.list_decisions()


@router.get("/rules", response_model=list[FirewallRule])
def list_rules(rpc_client: RpcClientDep) -> list[FirewallRule]:
    return rpc_client.list_rules()


@router.get("/events", response_model=list[SecurityEvent])
def list_events(rpc_client: RpcClientDep) -> list[SecurityEvent]:
    return rpc_client.list_events()


@router.get("/models", response_model=list[ModelMetadata])
def list_models(rpc_client: RpcClientDep) -> list[ModelMetadata]:
    return rpc_client.list_models()
