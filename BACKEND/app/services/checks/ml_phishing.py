"""Machine-learning phishing classification check using trained model and feature attribution."""

from app.schemas.scan import CheckCategory, CheckId, CheckStatus, Severity
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.context import ScanContext


class MlPhishingCheck(BaseCheck):
    """Evaluates URL phishing probability using machine learning model."""

    id = CheckId.ML_PHISHING
    name = "Machine-learning phishing model"
    category = CheckCategory.PHISHING
    source = "SafeLinks ML model"
    runs_in_quick_mode = True

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        predictor = ctx.ml_predictor
        if predictor is None or not getattr(predictor, "is_loaded", False):
            return CheckOutcome(
                status=CheckStatus.SKIPPED,
                severity=Severity.INFO,
                title="Model not trained yet",
                detail="Machine-learning phishing model is not loaded on this instance.",
                evidence=["Trained model artifact was not found."],
                signal="soft",
                points=None,
            )

        try:
            pred = await predictor.predict_async(ctx.submitted_url)
        except Exception as e:
            return CheckOutcome(
                status=CheckStatus.ERROR,
                severity=Severity.INFO,
                title="Inference failed",
                detail=f"Error executing model inference: {e}",
                evidence=[],
                signal="soft",
            )

        prob = float(pred.get("phishing_probability", 0.0))
        points = int(round(prob * 100))
        points = max(0, min(100, points))

        # Severity mapping
        if prob < 0.2:
            severity = Severity.INFO
        elif prob < 0.4:
            severity = Severity.LOW
        elif prob < 0.6:
            severity = Severity.MEDIUM
        elif prob < 0.8:
            severity = Severity.HIGH
        else:
            severity = Severity.CRITICAL

        title = "Looks like a phishing URL" if prob >= 0.5 else "No phishing pattern found"
        detail = f"ML model estimated a {prob:.1%} probability of phishing based on lexical and structural features."

        evidence: list[str] = []
        top_features = pred.get("top_features", [])
        for feat in top_features:
            impact = feat.get("impact", 0.0)
            name = feat.get("name", "")
            val = feat.get("value")
            if impact > 0:
                evidence.append(f"Risk factor: {name} = {val} (+{impact:.2f})")
            elif impact < 0:
                evidence.append(f"Safety factor: {name} = {val} ({impact:.2f})")

        return CheckOutcome(
            status=CheckStatus.DONE,
            severity=severity,
            title=title,
            detail=detail,
            evidence=evidence,
            points=points,
            signal="soft",
            data={"ml": pred},
        )
