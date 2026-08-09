from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


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
        if candidate.lower() in normalized:
            return normalized[candidate.lower()]

    if required:
        raise ValueError(
            f"Missing required column. "
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


def adapt_unsw_file(
    path: str | Path,
) -> pd.DataFrame:

    path = Path(path)

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    if df.empty:
        raise ValueError(
            f"UNSW file is empty: {path}"
        )

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    flow_id_column = _find_column(
        df,
        ["id"],
        required=True,
    )

    flow_id = df[
        flow_id_column
    ].astype("string")

    timestamp = _text(
        df,
        ["timestamp", "Timestamp"],
    )

    src_ip = _text(
        df,
        ["srcip", "src_ip", "source_ip"],
    )

    dst_ip = _text(
        df,
        ["dstip", "dst_ip", "destination_ip"],
    )

    src_port = _numeric(
        df,
        ["sport", "srcport", "src_port"],
    )

    dst_port = _numeric(
        df,
        ["dsport", "dstport", "dst_port"],
    )

    # ------------------------------------------------------------------
    # Protocol
    # ------------------------------------------------------------------

    protocol_column = _find_column(
        df,
        ["proto"],
        required=True,
    )

    protocol_text = (
        df[protocol_column]
        .astype("string")
        .str.strip()
        .str.lower()
    )

    categories = sorted(
        protocol_text
        .dropna()
        .unique()
        .tolist()
    )

    protocol_mapping = {
        value: index + 1
        for index, value in enumerate(categories)
    }

    protocol = protocol_text.map(
        protocol_mapping
    ).astype("float64")

    # ------------------------------------------------------------------
    # Core features
    # ------------------------------------------------------------------

    flow_duration = _numeric(
        df,
        ["dur"],
    )

    fwd_packets = _numeric(
        df,
        ["spkts"],
    )

    bwd_packets = _numeric(
        df,
        ["dpkts"],
    )

    fwd_bytes = _numeric(
        df,
        ["sbytes"],
    )

    bwd_bytes = _numeric(
        df,
        ["dbytes"],
    )

    fwd_packet_length_mean = _numeric(
        df,
        ["smean"],
    )

    bwd_packet_length_mean = _numeric(
        df,
        ["dmean"],
    )

    fwd_interarrival_mean = (
        _numeric(df, ["sinpkt"])
        / 1000.0
    )

    bwd_interarrival_mean = (
        _numeric(df, ["dinpkt"])
        / 1000.0
    )

    fwd_jitter = (
        _numeric(df, ["sjit"])
        / 1000.0
    )

    bwd_jitter = (
        _numeric(df, ["djit"])
        / 1000.0
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
        ["label"],
        required=True,
    )

    label = pd.to_numeric(
        df[label_column],
        errors="coerce",
    )

    attack_category_column = _find_column(
        df,
        ["attack_cat"],
    )

    if attack_category_column is None:
        attack_category = pd.Series(
            "Unknown",
            index=df.index,
            dtype="string",
        )
    else:
        attack_category = (
            df[attack_category_column]
            .astype("string")
            .fillna("Normal")
            .str.strip()
        )

    # ------------------------------------------------------------------
    # Canonical dataframe
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

            "flow_packets_per_sec":
                flow_packets_per_sec,

            "fwd_packets_per_sec":
                fwd_packets_per_sec,

            "bwd_packets_per_sec":
                bwd_packets_per_sec,

            "flow_bytes_per_sec":
                flow_bytes_per_sec,

            "fwd_bytes_per_sec":
                fwd_bytes_per_sec,

            "bwd_bytes_per_sec":
                bwd_bytes_per_sec,

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
                "UNSW-NB15",

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