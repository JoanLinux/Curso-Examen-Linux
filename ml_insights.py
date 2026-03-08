from __future__ import annotations

from typing import Dict, List


def _clamp01(x: float) -> float:
    if x < 0:
        return 0.0
    if x > 1:
        return 1.0
    return float(x)


def _heuristic_risk(features: Dict) -> float:
    wrong_rate = float(features.get("wrong_rate", 0.0))
    median_time = float(features.get("median_time_topic", 0.0))
    resets = float(features.get("resets", 0.0))
    dropouts = float(features.get("dropouts", 0.0))
    syntax_ratio = float(features.get("syntax_error_ratio", 0.0))
    # Escala simple y estable para no depender de paquetes externos.
    raw = (
        wrong_rate * 0.45
        + min(median_time / 180.0, 1.0) * 0.20
        + min(resets / 5.0, 1.0) * 0.15
        + min(dropouts / 4.0, 1.0) * 0.10
        + syntax_ratio * 0.10
    )
    return _clamp01(raw)


def _risk_level(prob: float) -> str:
    if prob >= 0.67:
        return "alto"
    if prob >= 0.40:
        return "medio"
    return "bajo"


def build_ml_risk(student_feature_rows: List[Dict]) -> Dict[str, Dict]:
    """
    Retorna riesgo por alumno con enfoque independiente:
    - Intenta IsolationForest si scikit-learn esta disponible.
    - Si no, usa modelo heuristico local.
    """
    if not student_feature_rows:
        return {}

    by_key = {}
    for row in student_feature_rows:
        k = row.get("student_key")
        if k:
            by_key[k] = {"risk_prob": _heuristic_risk(row), "model": "heuristic"}

    # Ruta ML opcional, sin instalar ni modificar entornos globales.
    try:
        from sklearn.ensemble import IsolationForest  # type: ignore
    except Exception:
        return {
            k: {**v, "risk_level": _risk_level(v["risk_prob"])}
            for k, v in by_key.items()
        }

    if len(student_feature_rows) < 6:
        return {
            k: {**v, "risk_level": _risk_level(v["risk_prob"])}
            for k, v in by_key.items()
        }

    X = []
    keys = []
    for row in student_feature_rows:
        k = row.get("student_key")
        if not k:
            continue
        keys.append(k)
        X.append(
            [
                float(row.get("wrong_rate", 0.0)),
                float(row.get("median_time_topic", 0.0)),
                float(row.get("resets", 0.0)),
                float(row.get("dropouts", 0.0)),
                float(row.get("syntax_error_ratio", 0.0)),
            ]
        )

    try:
        iso = IsolationForest(contamination=0.25, random_state=42)
        iso.fit(X)
        # score_samples: mayor es mas normal. Invertimos para riesgo.
        scores = iso.score_samples(X)
        lo = min(scores)
        hi = max(scores)
        span = (hi - lo) or 1.0
        for i, k in enumerate(keys):
            normal01 = (scores[i] - lo) / span
            risk_prob = _clamp01(1.0 - normal01)
            by_key[k] = {"risk_prob": risk_prob, "model": "isolation_forest"}
    except Exception:
        # fallback silencioso a heuristico
        pass

    return {
        k: {**v, "risk_level": _risk_level(v["risk_prob"])}
        for k, v in by_key.items()
    }

