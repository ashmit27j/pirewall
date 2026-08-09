from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


# ----------------------------------------------------------------------
# Canonical schema
# ----------------------------------------------------------------------

METADATA_COLUMNS = [
    "flow_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
]

CANONICAL_FEATURES = [
    "protocol",
    "flow_duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "flow_packets_per_sec",
    "fwd_packets_per_sec",
    "bwd_packets_per_sec",
    "flow_bytes_per_sec",
    "fwd_bytes_per_sec",
    "bwd_bytes_per_sec",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "fwd_interarrival_mean",
    "bwd_interarrival_mean",
    "fwd_jitter",
    "bwd_jitter",
    "fwd_bwd_packet_ratio",
    "fwd_bwd_byte_ratio",
]

LABEL_COLUMNS = [
    "dataset",
    "attack_category",
    "label",
]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _find_column(
    df: pd.DataFrame,
    candidates: list[str],
    required: bool = False,
) -> str | None:

    normalized = {
        str(column).strip().lower(): column
        for column in df.columns
    }

    for candidate in candidates:
        key = candidate.strip().lower()

        if key in normalized:
            return normalized[key]

    if required:
        raise ValueError(
            f"Could not find required column. "
            f"Tried: {candidates}"
        )

    return None


def _numeric(
    df: pd.DataFrame,
    candidates: list[str],
) -> pd.Series:

    column = _find_column(df, candidates)

    if column is None:
        return pd.Series(
            np.nan,
            index=df.index,
            dtype="float64",
        )

    return pd.to_numeric(
        df[column],
        errors="coerce",
    )


def _text(
    df: pd.DataFrame,
    candidates: list[str],
) -> pd.Series:

    column = _find_column(df, candidates)

    if column is None:
        return pd.Series(
            pd.NA,
            index=df.index,
            dtype="string",
        )

    return df[column].astype("string")


def _safe_divide(
    numerator: pd.Series,
    denominator: pd.Series,
) -> pd.Series:

    numerator = pd.to_numeric(
        numerator,
        errors="coerce",
    )

    denominator = pd.to_numeric(
        denominator,
        errors="coerce",
    )

    result = pd.Series(
        0.0,
        index=numerator.index,
        dtype="float64",
    )

    valid = (
        numerator.notna()
        & denominator.notna()
        & denominator.ne(0)
    )

    result.loc[valid] = (
        numerator.loc[valid]
        / denominator.loc[valid]
    )

    return result.replace(
        [np.inf, -np.inf],
        np.nan,
    )


# ----------------------------------------------------------------------
# Adapter
# ----------------------------------------------------------------------

def adapt_cicids_file(
    path: str | Path,
) -> pd.DataFrame:

    path = Path(path)

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    if df.empty:
        raise ValueError(
            f"CICIDS file is empty: {path}"
        )

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    flow_id = pd.Series(
        df.index.astype(str),
        index=df.index,
        dtype="string",
    )

    timestamp = _text(
        df,
        [
            "Timestamp",
            "timestamp",
        ],
    )

    src_ip = _text(
        df,
        [
            "Source IP",
            "Src IP",
            "SourceIP",
            "src_ip",
        ],
    )

    dst_ip = _text(
        df,
        [
            "Destination IP",
            "Dst IP",
            "DestinationIP",
            "dst_ip",
        ],
    )

    src_port = _numeric(
        df,
        [
            "Source Port",
            "Src Port",
            "src_port",
        ],
    )

    dst_port = _numeric(
        df,
        [
            "Destination Port",
            "Dst Port",
            "dst_port",
        ],
    )

    # ------------------------------------------------------------------
    # Protocol
    # ------------------------------------------------------------------

    protocol = _numeric(
        df,
        [
            "Protocol",
            "protocol",
        ],
    )

    # ------------------------------------------------------------------
    # Base features
    # ------------------------------------------------------------------

    flow_duration = _numeric(
        df,
        ["Flow Duration"],
    )

    fwd_packets = _numeric(
        df,
        ["Total Fwd Packets"],
    )

    bwd_packets = _numeric(
        df,
        ["Total Backward Packets"],
    )

    fwd_bytes = _numeric(
        df,
        ["Total Length of Fwd Packets"],
    )

    bwd_bytes = _numeric(
        df,
        ["Total Length of Bwd Packets"],
    )

    fwd_packet_length_mean = _numeric(
        df,
        ["Fwd Packet Length Mean"],
    )

    bwd_packet_length_mean = _numeric(
        df,
        ["Bwd Packet Length Mean"],
    )

    # CICIDS timing values are in microseconds.
    flow_duration = flow_duration / 1_000_000.0

    fwd_interarrival_mean = (
        _numeric(df, ["Fwd IAT Mean"])
        / 1_000_000.0
    )

    bwd_interarrival_mean = (
        _numeric(df, ["Bwd IAT Mean"])
        / 1_000_000.0
    )

    fwd_jitter = (
        _numeric(df, ["Fwd IAT Std"])
        / 1_000_000.0
    )

    bwd_jitter = (
        _numeric(df, ["Bwd IAT Std"])
        / 1_000_000.0
    )

    # ------------------------------------------------------------------
    # Rates
    # ------------------------------------------------------------------

    flow_packets_per_sec = _safe_divide(
        fwd_packets + bwd_packets,
        flow_duration,
    )

    fwd_packets_per_sec = _safe_divide(
        fwd_packets,
        flow_duration,
    )

    bwd_packets_per_sec = _safe_divide(
        bwd_packets,
        flow_duration,
    )

    flow_bytes_per_sec = _safe_divide(
        fwd_bytes + bwd_bytes,
        flow_duration,
    )

    fwd_bytes_per_sec = _safe_divide(
        fwd_bytes,
        flow_duration,
    )

    bwd_bytes_per_sec = _safe_divide(
        bwd_bytes,
        flow_duration,
    )

    # ------------------------------------------------------------------
    # Ratios
    # ------------------------------------------------------------------

    fwd_bwd_packet_ratio = _safe_divide(
        fwd_packets,
        bwd_packets,
    )

    fwd_bwd_byte_ratio = _safe_divide(
        fwd_bytes,
        bwd_bytes,
    )

    # ------------------------------------------------------------------
    # Labels
    # ------------------------------------------------------------------

    label_column = _find_column(
        df,
        ["Label"],
        required=True,
    )

    raw_label = (
        df[label_column]
        .astype("string")
        .str.strip()
    )

    label = (
        raw_label
        .str.upper()
        .ne("BENIGN")
        .astype("int8")
    )

    attack_category = raw_label.apply(
        lambda value: (
            "BENIGN"
            if str(value).upper() == "BENIGN"
            else str(value)
        )
    ).astype("string")

    # ------------------------------------------------------------------
    # Construct canonical dataframe
    # ------------------------------------------------------------------

    result = pd.DataFrame(
        {
            "flow_id": flow_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,

            "protocol": protocol,

            "flow_duration": flow_duration,
            "fwd_packets": fwd_packets,
            "bwd_packets": bwd_packets,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,

            "flow_packets_per_sec": flow_packets_per_sec,
            "fwd_packets_per_sec": fwd_packets_per_sec,
            "bwd_packets_per_sec": bwd_packets_per_sec,

            "flow_bytes_per_sec": flow_bytes_per_sec,
            "fwd_bytes_per_sec": fwd_bytes_per_sec,
            "bwd_bytes_per_sec": bwd_bytes_per_sec,

            "fwd_packet_length_mean":
                fwd_packet_length_mean,

            "bwd_packet_length_mean":
                bwd_packet_length_mean,

            "fwd_interarrival_mean":
                fwd_interarrival_mean,

            "bwd_interarrival_mean":
                bwd_interarrival_mean,

            "fwd_jitter":
                fwd_jitter,

            "bwd_jitter":
                bwd_jitter,

            "fwd_bwd_packet_ratio":
                fwd_bwd_packet_ratio,

            "fwd_bwd_byte_ratio":
                fwd_bwd_byte_ratio,

            "dataset":
                "CICIDS2017",

            "attack_category":
                attack_category,

            "label":
                label,
        }
    )

    # ------------------------------------------------------------------
    # Remove invalid flows
    # ------------------------------------------------------------------

    result = result[
        result["flow_duration"].notna()
        & (result["flow_duration"] > 0)
    ].copy()

    result.reset_index(
        drop=True,
        inplace=True,
    )

    return result