"""Generates a synthetic labeled dataset for training pipeline testing and CI."""

import argparse
import csv
from pathlib import Path

BENIGN_SAMPLES = [
    "https://google.com/",
    "https://google.com/search?q=python",
    "https://microsoft.com/en-us/windows",
    "https://apple.com/iphone-16-pro",
    "https://amazon.com/dp/B08N5WRWNW",
    "https://amazon.com/gp/help/customer/display.html",
    "https://wikipedia.org/wiki/Phishing",
    "https://github.com/fastapi/fastapi",
    "https://github.com/features/copilot",
    "https://stackoverflow.com/questions/tagged/python",
    "https://python.org/downloads/release/python-3120/",
    "https://cloudflare.com/learning/ssl/what-is-ssl/",
    "https://netflix.com/browse",
    "https://spotify.com/us/premium/",
    "https://nytimes.com/section/technology",
    "https://cnn.com/world",
    "https://bbc.com/news/technology",
    "https://reddit.com/r/Python/",
    "https://medium.com/topic/cybersecurity",
    "https://linkedin.com/jobs/view/123456",
    "https://mozilla.org/en-US/firefox/new/",
    "https://apache.org/licenses/",
    "https://pypi.org/project/fastapi/",
    "https://docs.python.org/3/library/asyncio.html",
    "https://facebook.com/help",
    "https://instagram.com/explore/",
    "https://twitch.tv/directory",
    "https://dropbox.com/features/share",
    "https://zoom.us/pricing",
    "https://slack.com/resources",
]

PHISHING_SAMPLES = [
    "http://paypal.login-verification-account.xyz/signin",
    "http://appleid.apple-support-verify.top/auth/login.php",
    "http://192.168.1.100/admin/secure/login",
    "http://wellsfargo.account-recovery-service.click/billing",
    "http://chase.online-banking-update.zip/confirm?token=489123",
    "http://netflix.billing-suspended-reactivate.icu/user/login",
    "http://amazon.orders-verification-update.buzz/claim/reward",
    "http://microsoft.account-security-alert.work/unlock",
    "http://binance.wallet-verification-bonus.cf/claim.php",
    "http://coinbase.pro-recovery-session.ml/login/auth",
    "http://dhl.parcel-tracking-invoice.gq/package/delivery",
    "http://fedex.shipment-customs-fee.sbs/pay/invoice.php",
    "http://metamask.seed-recovery-wallet.cyou/connect",
    "http://google.account-password-reset.top/recovery",
    "http://instagram.copyright-infringement-appeal.xyz/badge",
    "http://whatsapp.web-qr-connect.icu/scan/auth.apk",
    "http://facebook.security-checkpoint-appeal.fit/confirm",
    "http://steam.community-free-gifts.rest/trade/offer",
    "http://roblox.free-robux-generator.monster/verify",
    "http://bankofamerica.secure-banking-portal.win/signin",
    "http://citibank.card-security-alert.cam/update",
    "http://user:pass@secure-auth-login.top/account/verify",
    "http://0x7f000001/phishing/payload.exe",
    "http://2130706433/login/banking",
    "http://verify-identity-secure-login-account-update.xyz/auth",
    "http://bit.ly/3xFakeBankLogin",
    "http://tinyurl.com/crypto-giveaway-claim",
    "http://secure.login.account.update.verify.evil.com/auth",
    "http://chase-bank-verify-identity-update-billing.top/session",
    "http://portal.login-security.sbs/webscr?cmd=_login-run",
]


def generate_synthetic_dataset(output_path: Path) -> Path:
    """Writes balanced synthetic URL dataset for testing."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, int]] = []
    for u in BENIGN_SAMPLES:
        rows.append((u, 0))
    for u in PHISHING_SAMPLES:
        rows.append((u, 1))

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url, label in rows:
            writer.writerow([url, label])

    print(f"Generated synthetic dataset with {len(rows)} samples ({len(BENIGN_SAMPLES)} benign, {len(PHISHING_SAMPLES)} phishing) at {output_path}")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic URL phishing dataset.")
    parser.add_argument(
        "--out",
        type=str,
        default="app/ml/data/urls_SYNTHETIC.csv",
        help="Target output CSV file path",
    )
    args = parser.parse_args()
    generate_synthetic_dataset(Path(args.out))


if __name__ == "__main__":
    main()
