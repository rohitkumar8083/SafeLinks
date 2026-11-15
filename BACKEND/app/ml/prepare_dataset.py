"""CLI tool to prepare, clean, and balance phishing and benign training datasets."""

import argparse
import csv
import logging
import random
from pathlib import Path
from urllib.parse import urlparse

import tldextract

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_tld_extractor = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=None, include_psl_private_domains=True)

# Plausible paths to blend into benign domains so model doesn't overfit to 'path presence'
BENIGN_PATH_TEMPLATES = [
    "",
    "/",
    "/about",
    "/about-us",
    "/contact",
    "/help",
    "/faq",
    "/terms",
    "/privacy",
    "/login",
    "/signin",
    "/account",
    "/products/123",
    "/items/view?id=459",
    "/blog/security-best-practices",
    "/news/2026/updates",
    "/search?q=cybersecurity",
    "/docs/getting-started",
    "/pricing",
    "/features",
]


def _get_registered_domain(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
        ext = _tld_extractor(host)
        reg = getattr(ext, "top_domain_under_public_suffix", None) or host
        return reg or host
    except Exception:
        return ""


def clean_url(raw: str) -> str | None:
    """Validates and cleans a raw URL line."""
    url = raw.strip()
    if not url or len(url) > 2048:
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return None
        return url
    except Exception:
        return None


def prepare_dataset(
    phishing_file: Path,
    benign_file: Path,
    output_file: Path,
    balance_ratio: float = 1.0,
    seed: int = 42,
) -> None:
    """Reads raw phishing and benign exports, generates paths, dedupes, and writes balanced CSV."""
    random.seed(seed)
    phishing_urls: set[str] = set()
    benign_urls: set[str] = set()

    # 1. Process phishing source
    if phishing_file.exists():
        logger.info("Reading phishing URLs from %s", phishing_file)
        with phishing_file.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                c = clean_url(line)
                if c:
                    phishing_urls.add(c)
    else:
        logger.warning("Phishing raw file not found at %s", phishing_file)

    # 2. Process benign source
    if benign_file.exists():
        logger.info("Reading benign domains from %s", benign_file)
        with benign_file.open("r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                domain = row[1].strip() if len(row) > 1 else row[0].strip()
                if not domain or domain.lower() in ("domain", "rank"):
                    continue
                # Blend with plausible paths
                template = random.choice(BENIGN_PATH_TEMPLATES)
                scheme = "https://" if random.random() > 0.1 else "http://"
                full_url = f"{scheme}{domain}{template}"
                c = clean_url(full_url)
                if c:
                    benign_urls.add(c)
    else:
        logger.warning("Benign raw file not found at %s", benign_file)

    # Deduplicate against each other (drop overlap)
    overlap = phishing_urls.intersection(benign_urls)
    if overlap:
        logger.info("Removing %d overlapping URLs between classes", len(overlap))
        phishing_urls.difference_update(overlap)
        benign_urls.difference_update(overlap)

    n_phish = len(phishing_urls)
    n_benign = len(benign_urls)
    logger.info("Raw counts before balancing: Phishing=%d, Benign=%d", n_phish, n_benign)

    if n_phish == 0 and n_benign == 0:
        logger.error("No valid URLs found in inputs.")
        return

    # Balance classes (downsample majority class)
    phish_list = list(phishing_urls)
    benign_list = list(benign_urls)

    if n_phish > 0 and n_benign > 0:
        target_phish = min(n_phish, int(n_benign * balance_ratio))
        target_benign = min(n_benign, int(n_phish / balance_ratio))
        random.shuffle(phish_list)
        random.shuffle(benign_list)
        final_phish = phish_list[:target_phish]
        final_benign = benign_list[:target_benign]
    else:
        final_phish = phish_list
        final_benign = benign_list

    combined: list[tuple[str, int]] = [(u, 1) for u in final_phish] + [(u, 0) for u in final_benign]
    random.shuffle(combined)

    # Write output CSV
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url, label in combined:
            writer.writerow([url, label])

    # Calculate unique domains
    phish_domains = {_get_registered_domain(u) for u in final_phish}
    benign_domains = {_get_registered_domain(u) for u in final_benign}

    print("\n--- Dataset Preparation Summary ---")
    print(f"Output File: {output_file}")
    print(f"Total Rows: {len(combined)}")
    print(f"Phishing (1): {len(final_phish)} (across {len(phish_domains)} unique domains)")
    print(f"Benign (0):   {len(final_benign)} (across {len(benign_domains)} unique domains)")
    print("-----------------------------------\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare balanced SafeLinks URL dataset.")
    parser.add_argument("--phishing", type=str, default="app/ml/data/raw/phishing.txt")
    parser.add_argument("--benign", type=str, default="app/ml/data/raw/benign_domains.csv")
    parser.add_argument("--out", type=str, default="app/ml/data/urls.csv")
    parser.add_argument("--ratio", type=float, default=1.0, help="Ratio of phishing to benign samples")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    prepare_dataset(
        phishing_file=Path(args.phishing),
        benign_file=Path(args.benign),
        output_file=Path(args.out),
        balance_ratio=args.ratio,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
