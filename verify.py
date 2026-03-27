"""Version 1: minimal claim verification report structure."""


def verify_claim(claim):
    """Print a simple structured verification report for a claim."""
    print("=" * 60)
    print("CLAIM")
    print("-" * 60)
    print(claim)
    print()

    print("SOURCES")
    print("-" * 60)
    print("1. Cerebras Benchmark or product page describing inference performance")
    print("2. Nvidia documentation or third party benchmark describing GPU inference architecture")
    print()

    print("FACTS")
    print("-" * 60)
    print("1. Cerebras reports lower latency or higher tokens per second for some large model inference workloads")
    print("2. Nvidia large model inference uses multi GPU systems with interconnect overhead")
    print()

    print("GAPS / CONTRADICTIONS")
    print("-" * 60)
    print("1. Benchmark conditions may differ across vendors and may not be directly comparable")
    print("2. Vendor reported performance may not generalize across all models and workloads")
    print()

    print("VERDICT")
    print("-" * 60)
    print("PARTIALLY VERIFIED")
    print("=" * 60)


if __name__ == "__main__":
    sample_claim = (
        "Cerebras delivers significantly lower latency than Nvidia "
        "for large model inference"
    )
    verify_claim(sample_claim)
