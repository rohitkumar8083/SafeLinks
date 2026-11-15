# SafeLinks ML Data Directory

This directory stores raw intelligence exports and preprocessed datasets for training the phishing classifier model.

## Raw Source Files
To train a production model on real-world data, download the following files and place them in `app/ml/data/raw/`:

1. **Phishing URLs**:
   - Source: [OpenPhish Feed](https://openphish.com/feed.txt) or [PhishTank Database Export](https://www.phishtank.com/developer_info.php).
   - Expected path: `app/ml/data/raw/phishing.txt`
   - Format: Plain text, one URL per line.

2. **Benign Domains**:
   - Source: [Tranco Top 1M Sites List](https://tranco-list.eu/).
   - Expected path: `app/ml/data/raw/benign_domains.csv`
   - Format: CSV with columns `rank,domain` (e.g. `1,google.com`).

## Generating Training CSV
Run the preparation script to clean, deduplicate, synthesize paths, and balance the classes:
```bash
python -m app.ml.prepare_dataset --phishing app/ml/data/raw/phishing.txt --benign app/ml/data/raw/benign_domains.csv --out app/ml/data/urls.csv
```

## Testing / Synthetic Dataset
For local testing and CI/CD validation without downloading external lists, generate the synthetic dataset:
```bash
python -m scripts.make_synthetic_dataset --out app/ml/data/urls_SYNTHETIC.csv
```
