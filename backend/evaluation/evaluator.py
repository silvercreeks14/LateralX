"""
Model quality evaluator for FIP.

Runs three evaluations:
  1. LMD Random Forest  — classification accuracy, precision, recall, F1, confusion matrix
  2. MITRE ATT&CK mapper — keyword coverage against a ground-truth technique set
  3. Isolation Forest   — anomaly detection ROC (TPR @ FPR ≤ 0.10)

All inputs are the embedded ground-truth benchmark in datasets.py, whose events
are structured after OTRF/Security-Datasets (github.com/OTRF/Security-Datasets).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime

import numpy as np

from backend.evaluation.datasets import (
    LMD_BENCHMARK, MITRE_BENCHMARK, DATASET_CITATIONS, CLASS_LABELS,
    CLS_NORMAL,
)

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _safe_div(a: float, b: float) -> float:
    return round(a / b, 4) if b else 0.0


def _grade(f1: float) -> str:
    if f1 >= 0.90: return "A"
    if f1 >= 0.80: return "B"
    if f1 >= 0.65: return "C"
    return "D"


def _cm_to_dict(cm: np.ndarray, labels: list[str]) -> list[list[int]]:
    return [[int(v) for v in row] for row in cm]


# ─────────────────────────────────────────────────────────────────────────────
# 1. LMD Random Forest evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_lmd() -> dict:
    """
    Run the LMD model against the ground-truth benchmark.
    Returns a dict matching the ModelBenchmarkResult schema.
    """
    from backend.analysis.lmd_model import run_lmd_full, _ATTACK_CLASSES

    events    = [item["event"] for item in LMD_BENCHMARK]
    y_true    = [item["ground_truth_class"] for item in LMD_BENCHMARK]
    datasets  = [item["dataset"] for item in LMD_BENCHMARK]

    result = run_lmd_full(events)

    # Map event index → predicted class (default 0 = Normal)
    pred_map: dict[int, int] = {d["event_index"]: d["attack_class"]
                                 for d in result["detections"]}
    y_pred = [pred_map.get(i, 0) for i in range(len(events))]

    n_classes = len(CLASS_LABELS)
    classes   = list(range(n_classes))

    # Build confusion matrix
    cm = np.zeros((n_classes, n_classes), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t][p] += 1

    # Per-class metrics
    class_metrics = []
    for cls in classes:
        tp = int(cm[cls, cls])
        fp = int(cm[:, cls].sum()) - tp
        fn = int(cm[cls, :].sum()) - tp
        prec   = _safe_div(tp, tp + fp)
        rec    = _safe_div(tp, tp + fn)
        f1     = _safe_div(2 * prec * rec, prec + rec)
        support = int(cm[cls, :].sum())
        class_metrics.append({
            "class_id":   cls,
            "class_name": CLASS_LABELS[cls],
            "precision":  prec,
            "recall":     rec,
            "f1":         f1,
            "support":    support,
        })

    correct    = int(np.trace(cm))
    total      = len(y_true)
    accuracy   = _safe_div(correct, total)
    attack_cls = [m for m in class_metrics if m["class_id"] != CLS_NORMAL]
    macro_p  = _safe_div(sum(m["precision"] for m in attack_cls), len(attack_cls))
    macro_r  = _safe_div(sum(m["recall"]    for m in attack_cls), len(attack_cls))
    macro_f1 = _safe_div(sum(m["f1"]        for m in attack_cls), len(attack_cls))

    # Per-dataset breakdown
    ds_results: dict[str, dict] = defaultdict(lambda: {"correct": 0, "total": 0})
    for i, (t, p, ds) in enumerate(zip(y_true, y_pred, datasets)):
        ds_results[ds]["total"] += 1
        if t == p:
            ds_results[ds]["correct"] += 1
    per_dataset = {
        ds: {
            "accuracy": _safe_div(v["correct"], v["total"]),
            "correct":  v["correct"],
            "total":    v["total"],
            "citation": DATASET_CITATIONS.get(ds, ds),
        }
        for ds, v in ds_results.items()
    }

    # Gap analysis
    gaps = []
    for m in class_metrics:
        if m["class_id"] == CLS_NORMAL:
            continue
        if m["recall"] < 0.80:
            gaps.append(
                f"{m['class_name']}: recall {m['recall']:.0%} — "
                f"add more keyword patterns or training samples for this class"
            )
        if m["precision"] < 0.80:
            gaps.append(
                f"{m['class_name']}: precision {m['precision']:.0%} — "
                f"consider tightening detection patterns to reduce false positives"
            )

    return {
        "model_name":       "LMD Random Forest (AD Attack Classifier)",
        "dataset_source":   "OTRF/Security-Datasets benchmark",
        "dataset_url":      "https://github.com/OTRF/Security-Datasets",
        "dataset_citation": (
            "Rodriguez, J. L. & Rodriguez, R. (2020). "
            "OTRF Security Datasets and Open Analytics Platform. "
            "github.com/OTRF/Security-Datasets"
        ),
        "n_samples":        total,
        "n_attack_samples": total - int(cm[CLS_NORMAL, :].sum()),
        "accuracy":         accuracy,
        "precision_macro":  macro_p,
        "recall_macro":     macro_r,
        "f1_macro":         macro_f1,
        "grade":            _grade(macro_f1),
        "class_metrics":    class_metrics,
        "confusion_matrix": _cm_to_dict(cm, [CLASS_LABELS[c] for c in classes]),
        "class_labels":     [CLASS_LABELS[c] for c in classes],
        "per_dataset":      per_dataset,
        "gaps":             gaps,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. MITRE ATT&CK mapper evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_mitre() -> dict:
    """
    Test mitre.py keyword coverage against the MITRE_BENCHMARK ground truth.
    For each (description, expected_techniques) pair, checks whether the
    mapper returns all expected technique IDs.
    """
    from backend.analysis.mitre import map_techniques
    from backend.schema import ForensicEvent, RawSource

    results = []
    hit = 0
    partial = 0
    miss = 0

    for desc, expected_ids in MITRE_BENCHMARK:
        ev = ForensicEvent(
            timestamp=datetime(2024, 1, 1),
            event_type="test",
            source_host="test",
            user="test",
            description=desc,
            raw_source=RawSource.GENERIC,
        )
        found = map_techniques([ev])
        found_ids = {t.id for t in found}
        expected  = set(expected_ids)

        matched = expected & found_ids
        missed  = expected - found_ids

        if len(matched) == len(expected):
            status = "hit"
            hit += 1
        elif matched:
            status = "partial"
            partial += 1
        else:
            status = "miss"
            miss += 1

        results.append({
            "description":   desc[:80] + ("…" if len(desc) > 80 else ""),
            "expected":      sorted(expected_ids),
            "found":         sorted(found_ids & expected),
            "missed":        sorted(missed),
            "status":        status,
        })

    total    = len(MITRE_BENCHMARK)
    coverage = _safe_div(hit + 0.5 * partial, total)
    f1_equiv = coverage  # proxy — full coverage = 1.0

    gaps = [r["description"] for r in results if r["status"] in ("miss", "partial")]

    return {
        "model_name":       "MITRE ATT&CK Keyword Mapper",
        "dataset_source":   "MITRE ATT&CK Knowledge Base v14 + OTRF technique descriptions",
        "dataset_url":      "https://attack.mitre.org",
        "dataset_citation": (
            "MITRE Corporation (2023). "
            "MITRE ATT&CK® Knowledge Base v14. attack.mitre.org"
        ),
        "n_samples":        total,
        "hits":             hit,
        "partials":         partial,
        "misses":           miss,
        "coverage":         coverage,
        "grade":            _grade(f1_equiv),
        "per_technique":    results,
        "gaps":             [
            f"No match for: {d}" for d in gaps
        ] if gaps else ["Full coverage — all techniques mapped"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3. Isolation Forest evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_anomaly() -> dict:
    """
    Evaluate the Isolation Forest using the LMD benchmark:
    - Normal events (class 0) = negative ground truth
    - Attack events (class != 0) = positive ground truth

    Measures TPR at FPR ≤ 0.10 and reports ROC AUC.
    Falls back gracefully if no trained model exists.
    """
    from backend.analysis.ml_anomaly import score_all_entities
    from backend.schema import ForensicEvent

    events   = [item["event"] for item in LMD_BENCHMARK]
    y_true_bin = [0 if item["ground_truth_class"] == CLS_NORMAL else 1
                  for item in LMD_BENCHMARK]

    try:
        scores = score_all_entities(events)
    except Exception as exc:
        log.warning("Isolation Forest evaluation failed: %s", exc)
        return {
            "model_name": "Isolation Forest (Behavioral Anomaly)",
            "grade": "N/A",
            "note": f"Model not trained yet or error: {exc}",
            "gaps": ["Train the Isolation Forest model first via the ML Training endpoint"],
        }

    # Map entity → anomaly score; aggregate to per-event proxy via source_host
    entity_score: dict[str, float] = {s.entity: s.anomaly_score for s in scores}
    event_scores = []
    for ev in events:
        # Use the highest score for this host as event-level proxy
        score = entity_score.get(ev.source_host,
                entity_score.get((ev.user or ""), 0.0))
        event_scores.append(score)

    # Compute ROC curve manually
    thresholds = sorted(set(event_scores), reverse=True)
    n_pos = sum(y_true_bin)
    n_neg = len(y_true_bin) - n_pos

    if n_pos == 0 or n_neg == 0:
        return {
            "model_name": "Isolation Forest (Behavioral Anomaly)",
            "grade": "N/A",
            "note": "Insufficient ground-truth labels for ROC computation",
            "gaps": [],
        }

    tpr_at_fpr10 = 0.0
    roc_points: list[dict] = []
    auc = 0.0
    prev_fpr = 0.0

    for thr in thresholds:
        tp = sum(1 for s, y in zip(event_scores, y_true_bin) if s >= thr and y == 1)
        fp = sum(1 for s, y in zip(event_scores, y_true_bin) if s >= thr and y == 0)
        tpr = _safe_div(tp, n_pos)
        fpr = _safe_div(fp, n_neg)
        roc_points.append({"threshold": round(thr, 3), "tpr": tpr, "fpr": fpr})
        if fpr <= 0.10:
            tpr_at_fpr10 = max(tpr_at_fpr10, tpr)
        auc += tpr * abs(fpr - prev_fpr)
        prev_fpr = fpr

    auc = round(min(auc, 1.0), 4)

    # For IF, grade on AUC
    f1_equiv = auc
    gaps: list[str] = []
    if tpr_at_fpr10 < 0.70:
        gaps.append(
            f"TPR@FPR≤10% is {tpr_at_fpr10:.0%} — "
            "retrain Isolation Forest on baseline logs from LANL dataset or "
            "production environment to improve AD-feature calibration"
        )
    if auc < 0.80:
        gaps.append(
            "AUC below 0.80 — consider adding more AD-specific features or "
            "tuning contamination parameter in IsolationForest"
        )

    return {
        "model_name":       "Isolation Forest (Behavioral Anomaly)",
        "dataset_source":   "OTRF/Security-Datasets benchmark (repurposed as binary labels)",
        "dataset_url":      "https://github.com/OTRF/Security-Datasets",
        "dataset_citation": (
            "Kent, A. D. (2015). "
            "Comprehensive, Multi-Source Cyber-Security Events. "
            "Scientific Data 2, 150014. (LANL dataset structure reference)"
        ),
        "n_samples":        len(events),
        "n_attack":         n_pos,
        "n_normal":         n_neg,
        "auc_roc":          auc,
        "tpr_at_fpr10":     round(tpr_at_fpr10, 4),
        "grade":            _grade(f1_equiv),
        "roc_curve":        roc_points[:30],   # first 30 points for chart
        "gaps":             gaps,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Master benchmark runner
# ─────────────────────────────────────────────────────────────────────────────

def run_full_benchmark() -> dict:
    """Run all three evaluations and return a combined BenchmarkReport dict."""
    log.info("Running full model benchmark…")
    run_at = datetime.utcnow().isoformat() + "Z"

    lmd_result     = evaluate_lmd()
    mitre_result   = evaluate_mitre()
    anomaly_result = evaluate_anomaly()

    grades = [lmd_result["grade"], mitre_result["grade"]]
    if anomaly_result.get("grade") not in (None, "N/A"):
        grades.append(anomaly_result["grade"])
    grade_order = {"A": 4, "B": 3, "C": 2, "D": 1}
    overall = min(grades, key=lambda g: grade_order.get(g, 0))

    all_gaps = (
        [f"[LMD] {g}"     for g in lmd_result.get("gaps", [])] +
        [f"[MITRE] {g}"   for g in mitre_result.get("gaps", [])] +
        [f"[Anomaly] {g}" for g in anomaly_result.get("gaps", [])]
    )

    recommendations = all_gaps or [
        "All models meet quality thresholds. "
        "Replace benchmark with live OTRF EVTX files for continuous validation."
    ]

    return {
        "run_at":          run_at,
        "overall_grade":   overall,
        "recommendations": recommendations,
        "lmd":             lmd_result,
        "mitre":           mitre_result,
        "anomaly":         anomaly_result,
        "benchmark_datasets": {
            k: v for k, v in DATASET_CITATIONS.items()
            if k in {
                "OTRF-Kerberoasting","OTRF-DCSync","OTRF-BloodHound",
                "OTRF-GoldenTicket","OTRF-LSASS","OTRF-PassHash",
                "OTRF-PsExec","OTRF-WMI","OTRF-DomainEnum","Normal-AD",
            }
        },
    }
