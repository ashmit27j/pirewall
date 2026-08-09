from __future__ import annotations

from pathlib import Path
import pandas as pd

from .cicids_adapter import (
    CANONICAL_FEATURES,
    METADATA_COLUMNS,
    adapt_cicids_file,
)

from .unsw_adapter import adapt_unsw_file


# ----------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DIR = PROJECT_ROOT / "datasets" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "datasets" / "processed"

CICIDS_DIR = RAW_DIR / "CIC-IDS- 2017"
UNSW_DIR = RAW_DIR / "UNSW-NB15"


# Exact CICIDS files that we want to process.
CICIDS_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]


def validate_schema(df: pd.DataFrame, name: str) -> None:
    """
    Ensure the processed dataframe follows the canonical schema.
    """
    expected = CANONICAL_FEATURES + METADATA_COLUMNS

    actual = list(df.columns)

    if actual != expected:
        raise ValueError(
            f"{name} has an invalid schema.\n"
            f"Expected:\n{expected}\n\n"
            f"Actual:\n{actual}"
        )


def process_cicids() -> pd.DataFrame:
    """
    Process all CICIDS2017 CSV files and concatenate them.
    """
    frames = []

    for filename in CICIDS_FILES:
        path = CICIDS_DIR / filename

        if not path.exists():
            raise FileNotFoundError(
                f"Missing CICIDS file: {path}"
            )

        frame = adapt_cicids_file(path)
        frames.append(frame)

    result = pd.concat(
        frames,
        ignore_index=True,
    )

    validate_schema(
        result,
        "CICIDS2017",
    )

    return result


def process_unsw(filename: str) -> pd.DataFrame:
    """
    Process one UNSW train/test CSV.
    """
    path = UNSW_DIR / filename

    if not path.exists():
        raise FileNotFoundError(
            f"Missing UNSW file: {path}"
        )

    result = adapt_unsw_file(path)

    validate_schema(
        result,
        filename,
    )

    return result


def save_dataframe(
    df: pd.DataFrame,
    filename: str,
) -> None:
    output_path = PROCESSED_DIR / filename

    print(f"Saving: {output_path}")

    df.to_csv(
        output_path,
        index=False,
    )


def print_summary(
    name: str,
    df: pd.DataFrame,
) -> None:
    print()
    print("=" * 70)
    print(name)
    print("=" * 70)

    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    print()
    print("Label distribution:")

    print(
        df["label"]
        .value_counts(dropna=False)
        .sort_index()
    )

    print()
    print("Missing values:")

    missing = (
        df.isna()
        .sum()
        .sort_values(ascending=False)
    )

    print(
        missing[missing > 0]
        .to_string()
        if (missing > 0).any()
        else "No missing values."
    )


def main() -> None:
    print("=" * 70)
    print("PiReWall Dataset Preprocessing")
    print("=" * 70)

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------------
    # CICIDS2017
    # --------------------------------------------------------------

    cicids = process_cicids()

    save_dataframe(
        cicids,
        "cicids2017_canonical.csv",
    )

    print_summary(
        "CICIDS2017 Canonical Dataset",
        cicids,
    )

    # --------------------------------------------------------------
    # UNSW-NB15 training set
    # --------------------------------------------------------------

    unsw_train = process_unsw(
        "UNSW_NB15_training-set.csv"
    )

    save_dataframe(
        unsw_train,
        "unsw_nb15_train_canonical.csv",
    )

    print_summary(
        "UNSW-NB15 Training Canonical Dataset",
        unsw_train,
    )

    # --------------------------------------------------------------
    # UNSW-NB15 testing set
    # --------------------------------------------------------------

    unsw_test = process_unsw(
        "UNSW_NB15_testing-set.csv"
    )

    save_dataframe(
        unsw_test,
        "unsw_nb15_test_canonical.csv",
    )

    print_summary(
        "UNSW-NB15 Testing Canonical Dataset",
        unsw_test,
    )

    # --------------------------------------------------------------
    # Cross-dataset schema validation
    # --------------------------------------------------------------

    if list(cicids.columns) != list(unsw_train.columns):
        raise RuntimeError(
            "CICIDS and UNSW training schemas do not match."
        )

    if list(cicids.columns) != list(unsw_test.columns):
        raise RuntimeError(
            "CICIDS and UNSW testing schemas do not match."
        )

    print()
    print("=" * 70)
    print("SUCCESS")
    print("=" * 70)
    print()
    print("Canonical datasets generated successfully.")
    print()
    print("Output files:")
    print(
        PROCESSED_DIR / "cicids2017_canonical.csv"
    )
    print(
        PROCESSED_DIR / "unsw_nb15_train_canonical.csv"
    )
    print(
        PROCESSED_DIR / "unsw_nb15_test_canonical.csv"
    )


if __name__ == "__main__":
    main()