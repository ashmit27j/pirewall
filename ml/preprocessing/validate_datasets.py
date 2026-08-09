from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROCESSED_DIR = (
    PROJECT_ROOT
    / "datasets"
    / "processed"
)


IDENTITY_COLUMNS = [
    "flow_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
]

ML_FEATURES = [
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

EXPECTED_COLUMNS = (
    IDENTITY_COLUMNS
    + ML_FEATURES
    + LABEL_COLUMNS
)


DATASET_FILES = {
    "CICIDS2017": "cicids2017_canonical.csv",
    "UNSW-NB15 Train": "unsw_nb15_train_canonical.csv",
    "UNSW-NB15 Test": "unsw_nb15_test_canonical.csv",
}


def header(title: str) -> None:
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def validate_schema(
    df: pd.DataFrame,
    name: str,
) -> bool:
    header(f"{name} — Schema")

    actual = list(df.columns)

    if actual == EXPECTED_COLUMNS:
        print(
            f"[PASS] {len(ML_FEATURES)} ML features"
        )
        print(
            f"[PASS] {len(IDENTITY_COLUMNS)} identity fields"
        )
        print(
            f"[PASS] {len(LABEL_COLUMNS)} label fields"
        )
        return True

    print("[FAIL] Schema mismatch.")

    missing = [
        c for c in EXPECTED_COLUMNS
        if c not in actual
    ]

    unexpected = [
        c for c in actual
        if c not in EXPECTED_COLUMNS
    ]

    if missing:
        print("\nMissing:")
        for c in missing:
            print(f"  - {c}")

    if unexpected:
        print("\nUnexpected:")
        for c in unexpected:
            print(f"  - {c}")

    return False


def validate_ml_types(
    df: pd.DataFrame,
    name: str,
) -> bool:
    header(f"{name} — ML Feature Types")

    passed = True

    for column in ML_FEATURES:
        if not pd.api.types.is_numeric_dtype(
            df[column]
        ):
            print(
                f"[FAIL] {column}: "
                f"{df[column].dtype}"
            )
            passed = False

    if passed:
        print(
            "[PASS] All ML features are numeric."
        )

    return passed


def validate_missing_ml_values(
    df: pd.DataFrame,
    name: str,
) -> bool:
    header(f"{name} — Missing ML Values")

    missing = df[ML_FEATURES].isna().sum()

    missing = missing[missing > 0]

    if missing.empty:
        print("[PASS] No missing ML values.")
        return True

    print(
        "[FAIL] Missing values in ML features:"
    )

    for column, count in missing.items():
        percentage = (
            count / len(df) * 100
        )

        print(
            f"  {column}: "
            f"{count:,} "
            f"({percentage:.4f}%)"
        )

    return False


def validate_infinite_values(
    df: pd.DataFrame,
    name: str,
) -> bool:
    header(f"{name} — Infinite Values")

    numeric = df[ML_FEATURES]

    infinite = (
        np.isinf(numeric)
        .sum()
    )

    total = int(infinite.sum())

    if total == 0:
        print(
            "[PASS] No infinite ML values."
        )
        return True

    print(
        f"[FAIL] {total:,} infinite values."
    )

    for column, count in infinite.items():
        if count:
            print(
                f"  {column}: {count:,}"
            )

    return False


def validate_durations(
    df: pd.DataFrame,
    name: str,
) -> bool:
    header(f"{name} — Flow Duration")

    negative = int(
        (df["flow_duration"] < 0).sum()
    )

    zero = int(
        (df["flow_duration"] == 0).sum()
    )

    if negative == 0 and zero == 0:
        print(
            "[PASS] All flow durations are positive."
        )
        return True

    if negative:
        print(
            f"[FAIL] Negative durations: "
            f"{negative:,}"
        )

    if zero:
        print(
            f"[FAIL] Zero durations: "
            f"{zero:,}"
        )

    return False


def validate_labels(
    df: pd.DataFrame,
    name: str,
) -> bool:
    header(f"{name} — Labels")

    if df["label"].isna().any():
        print("[FAIL] Missing labels.")
        return False

    values = set(
        df["label"].unique()
    )

    if not values.issubset({0, 1}):
        print(
            f"[FAIL] Invalid label values: "
            f"{values}"
        )
        return False

    print(
        df["label"]
        .value_counts()
        .sort_index()
        .to_string()
    )

    print(
        "\n[PASS] Binary labels are valid."
    )

    return True


def validate_identity(
    df: pd.DataFrame,
    name: str,
) -> bool:
    header(f"{name} — Identity Metadata")

    for column in IDENTITY_COLUMNS:
        populated = (
            df[column]
            .notna()
            .sum()
        )

        percentage = (
            populated / len(df) * 100
        )

        print(
            f"{column:15s}: "
            f"{populated:,}/{len(df):,} "
            f"({percentage:.2f}%)"
        )

    print(
        "\n[INFO] Missing identity metadata is "
        "allowed when the source dataset does "
        "not provide it."
    )

    return True


def validate_categories(
    df: pd.DataFrame,
    name: str,
) -> bool:
    header(
        f"{name} — Attack Categories"
    )

    print(
        df["attack_category"]
        .value_counts(dropna=False)
        .to_string()
    )

    if df["attack_category"].isna().any():
        print(
            "\n[FAIL] Missing attack categories."
        )
        return False

    print(
        "\n[PASS] Attack categories present."
    )

    return True


def print_statistics(
    df: pd.DataFrame,
    name: str,
) -> None:
    header(
        f"{name} — ML Feature Statistics"
    )

    stats = (
        df[ML_FEATURES]
        .describe()
        .T
    )

    print(
        stats[
            [
                "min",
                "mean",
                "std",
                "max",
            ]
        ].to_string(
            float_format=lambda x:
            f"{x:.6g}"
        )
    )


def validate_file(
    name: str,
    filename: str,
) -> tuple[bool, pd.DataFrame | None]:
    path = PROCESSED_DIR / filename

    header(f"Loading {name}")

    if not path.exists():
        print(
            f"[FAIL] Missing file: {path}"
        )
        return False, None

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    print(
        f"Rows: {len(df):,}"
    )

    print(
        f"Columns: {len(df.columns)}"
    )

    checks = [
        validate_schema(df, name),
        validate_ml_types(df, name),
        validate_missing_ml_values(
            df,
            name,
        ),
        validate_infinite_values(
            df,
            name,
        ),
        validate_durations(
            df,
            name,
        ),
        validate_labels(
            df,
            name,
        ),
        validate_identity(
            df,
            name,
        ),
        validate_categories(
            df,
            name,
        ),
    ]

    print_statistics(
        df,
        name,
    )

    return all(checks), df


def main() -> None:
    print("=" * 80)
    print(
        "PiReWall Canonical Dataset Validation"
    )
    print("=" * 80)

    results = {}

    for name, filename in DATASET_FILES.items():
        passed, _ = validate_file(
            name,
            filename,
        )

        results[name] = passed

    header("FINAL VALIDATION RESULT")

    for name, passed in results.items():
        print(
            f"{name}: "
            f"[{'PASS' if passed else 'FAIL'}]"
        )

    if all(results.values()):
        print()
        print(
            "ALL VALIDATION CHECKS PASSED."
        )
        print()
        print(
            "Canonical datasets are ready "
            "for model preprocessing."
        )
    else:
        print()
        print(
            "VALIDATION FAILED."
        )
        print(
            "Do not train the models yet."
        )


if __name__ == "__main__":
    main()