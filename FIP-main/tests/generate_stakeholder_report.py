"""
Stakeholder accuracy and performance report generator.

Produces a multi-panel PNG dashboard from live accuracy measurements.

Usage:
    python tests/generate_stakeholder_report.py

Output:
    reports/stakeholder_accuracy_report.png  — full dashboard (1600×1200)
    reports/mitre_detection_detail.png       — per-scenario MITRE breakdown
    reports/performance_benchmark.png        — throughput chart

Imports test data from test_accuracy_real.py — no separate data files needed.
"""
import sys
from pathlib import Path

# Allow imports from project root regardless of where the script is invoked
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib
matplotlib.use("Agg")  # headless — no display required

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import numpy as np

from tests.test_accuracy_real import collect_all_metrics

# ── Colour palette ─────────────────────────────────────────────────────────────
_GREEN  = "#2ecc71"
_ORANGE = "#f39c12"
_RED    = "#e74c3c"
_BLUE   = "#3498db"
_DARK   = "#2c3e50"
_GRAY   = "#95a5a6"
_LIGHT  = "#ecf0f1"
_PURPLE = "#9b59b6"

_SCENARIO_LABELS = {
    "ransomware":       "Ransomware\n(Ryuk/Conti)",
    "credential_theft": "Credential\nTheft",
    "powershell_c2":    "PowerShell\nC2 (Empire)",
    "kerberoasting":    "Kerbero-\nasting",
    "pass_the_hash":    "Pass the\nHash",
    "benign":           "Benign\nBaseline",
}


# ── Chart helpers ──────────────────────────────────────────────────────────────

def _bar_label(ax, bars, fmt="{:.0%}", offset=0.01, color="white", fontsize=9):
    for bar in bars:
        h = bar.get_height()
        if h > 0.05:
            ax.text(bar.get_x() + bar.get_width() / 2, h - offset,
                    fmt.format(h), ha="center", va="top",
                    fontsize=fontsize, color=color, fontweight="bold")


def _style_ax(ax, title: str, xlabel: str = "", ylabel: str = ""):
    ax.set_facecolor(_LIGHT)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_title(title, fontsize=11, fontweight="bold", color=_DARK, pad=8)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=9, color=_DARK)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=9, color=_DARK)
    ax.tick_params(colors=_DARK, labelsize=8)


# ── Individual chart functions ─────────────────────────────────────────────────

def _chart_component_overview(ax, m: dict):
    """Horizontal bar: F1/accuracy per pipeline component."""
    components = [
        ("MITRE Detection\n(Aggregate F1)", m["mitre"]["aggregate_attack_f1"]),
        ("IOC Extraction\n(Recall)", m["ioc"]["recall"]),
        ("Severity Scoring\n(Band Accuracy)", m["severity"]["band_accuracy"]),
        ("Anomaly: Attacker\nFlagged", 1.0 if m["anomaly"]["attacker_flagged"] else 0.0),
        ("Anomaly: Service Acct\nExcluded", 1.0 if m["anomaly"]["svc_backup_excluded"] else 0.0),
        ("Anomaly: Clean User\nNot Flagged", 1.0 if m["anomaly"]["alice_clean"] else 0.0),
    ]
    labels, values = zip(*components)
    colors = [_GREEN if v >= 0.80 else (_ORANGE if v >= 0.60 else _RED) for v in values]
    y = np.arange(len(labels))
    bars = ax.barh(y, values, color=colors, edgecolor="white", height=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlim(0, 1.15)
    ax.axvline(0.80, color=_DARK, linestyle="--", linewidth=0.8, alpha=0.5, label="80% threshold")
    for bar, val in zip(bars, values):
        ax.text(val + 0.02, bar.get_y() + bar.get_height() / 2,
                f"{val:.0%}", va="center", fontsize=9, color=_DARK, fontweight="bold")
    ax.legend(fontsize=7, loc="lower right")
    _style_ax(ax, "Component Accuracy Overview", xlabel="Score / Rate")


def _chart_mitre_per_scenario(ax, m: dict):
    """Grouped bars: precision / recall / F1 per attack scenario."""
    scenarios = [k for k in m["mitre"] if k not in ("aggregate_attack_f1", "benign_fp_count")]
    labels = [_SCENARIO_LABELS.get(s, s) for s in scenarios]
    precision = [m["mitre"][s]["precision"] for s in scenarios]
    recall    = [m["mitre"][s]["recall"]    for s in scenarios]
    f1        = [m["mitre"][s]["f1"]        for s in scenarios]

    x = np.arange(len(labels))
    w = 0.25
    ax.bar(x - w, precision, w, label="Precision", color=_BLUE,   edgecolor="white")
    ax.bar(x,     recall,    w, label="Recall",    color=_GREEN,  edgecolor="white")
    ax.bar(x + w, f1,        w, label="F1",        color=_PURPLE, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7.5)
    ax.set_ylim(0, 1.15)
    ax.axhline(0.80, color=_DARK, linestyle="--", linewidth=0.8, alpha=0.5)
    ax.legend(fontsize=8)
    _style_ax(ax, "MITRE ATT&CK Detection — Per Scenario", ylabel="Score")


def _chart_ioc_types(ax, m: dict):
    """Bar chart for IOC extraction counts by type."""
    # Reconstruct from metrics what we know
    ioc = m["ioc"]
    types_found = ioc.get("types_found", [])
    # We know specific IOC types planted in test_accuracy_real.py
    planned = {"ip": 1, "url": 1, "sha256": 1, "md5": 1, "registry_key": 1,
               "file_path": 1, "domain": 1}
    labels = list(planned.keys())
    found = [1 if t in types_found else 0 for t in labels]
    colors = [_GREEN if f else _RED for f in found]

    bars = ax.bar(labels, found, color=colors, edgecolor="white")
    ax.set_ylim(0, 1.5)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Not found", "Found"])
    for bar, val in zip(bars, found):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                "✓" if val else "✗", ha="center", fontsize=13,
                color=_GREEN if val else _RED)
    ax.tick_params(axis="x", rotation=30)
    _style_ax(ax, f"IOC Extraction by Type  (total={ioc['total_extracted']})",
              ylabel="Extracted")


def _chart_severity_scores(ax, m: dict):
    """Scatter + color bands showing actual severity scores vs expected bands."""
    severity = m["severity"]
    scenarios = [k for k in severity if k != "band_accuracy"]
    labels = [_SCENARIO_LABELS.get(s, s) for s in scenarios]
    scores = [severity[s]["score"] for s in scenarios]
    correct = [severity[s]["correct"] for s in scenarios]

    # Draw band zones
    ax.axhspan(0,  25, alpha=0.07, color=_GREEN,  label="LOW (<25)")
    ax.axhspan(25, 50, alpha=0.07, color=_ORANGE, label="MEDIUM (25-49)")
    ax.axhspan(50, 75, alpha=0.07, color=_RED,    label="HIGH (50-74)")
    ax.axhspan(75, 100, alpha=0.12, color="#c0392b", label="CRITICAL (75+)")

    x = np.arange(len(labels))
    colors = [_GREEN if c else _RED for c in correct]
    ax.scatter(x, scores, c=colors, s=120, zorder=5, edgecolors=_DARK, linewidths=0.8)
    ax.plot(x, scores, color=_GRAY, linewidth=1, zorder=4, linestyle="--")

    for xi, score, label_s in zip(x, scores, [severity[s]["label"] for s in scenarios]):
        ax.text(xi, score + 2.5, f"{score}\n{label_s}", ha="center",
                fontsize=7.5, color=_DARK, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7.5)
    ax.set_ylim(-5, 105)
    ax.legend(fontsize=7, loc="upper left")
    _style_ax(ax, f"Severity Scoring  (band accuracy={severity['band_accuracy']:.0%})",
              ylabel="Score (0–100)")


def _chart_performance(ax, m: dict):
    """Horizontal bar: events per second per component."""
    perf = m["performance"]
    components = [
        ("Severity\nScorer",    perf["severity_scorer_eps"]),
        ("MITRE\nMapper",       perf["mitre_mapper_eps"]),
        ("IOC\nExtractor",      perf["ioc_extractor_eps"]),
        ("Anomaly\nScorer",     perf["anomaly_scorer_eps"]),
    ]
    labels, values = zip(*components)
    colors = [_GREEN if v > 5000 else (_ORANGE if v > 500 else _RED) for v in values]
    y = np.arange(len(labels))
    bars = ax.barh(y, values, color=colors, edgecolor="white", height=0.5)

    for bar, val in zip(bars, values):
        ax.text(val + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:,} eps", va="center", fontsize=9, color=_DARK)

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xscale("log")
    ax.set_xlabel("Events per second (log scale)", fontsize=9)
    _style_ax(ax, f"Analysis Engine Throughput  (n={perf['n_events']:,} events)")


def _chart_summary_table(ax, m: dict):
    """Text summary panel — key metrics at a glance."""
    ax.set_axis_off()

    summary_lines = [
        ("MITRE Detection", ""),
        (f"  Aggregate F1:   {m['mitre']['aggregate_attack_f1']:.0%}", ""),
        (f"  Benign FPs:     {m['mitre']['benign_fp_count']} high-weight false positives", ""),
        ("", ""),
        ("IOC Extraction", ""),
        (f"  Recall:         {m['ioc']['recall']:.0%} of planted IOCs found", ""),
        (f"  Total extracted:{m['ioc']['total_extracted']} indicators", ""),
        (f"  Benign leaked:  {m['ioc']['benign_domains_leaked']} domains", ""),
        ("", ""),
        ("Severity Scoring", ""),
        (f"  Band accuracy:  {m['severity']['band_accuracy']:.0%}", ""),
        ("", ""),
        ("Anomaly Detection", ""),
        (f"  Attacker flagged:   {'YES' if m['anomaly']['attacker_flagged'] else 'NO'}", ""),
        (f"  Service acct excl:  {'YES' if m['anomaly']['svc_backup_excluded'] else 'NO'}", ""),
        (f"  Clean user clear:   {'YES' if m['anomaly']['alice_clean'] else 'NO'}", ""),
        ("", ""),
        ("Performance", ""),
        (f"  MITRE mapper:   {m['performance']['mitre_mapper_eps']:,} eps", ""),
        (f"  IOC extractor:  {m['performance']['ioc_extractor_eps']:,} eps", ""),
        (f"  Anomaly scorer: {m['performance']['anomaly_scorer_eps']:,} eps", ""),
    ]

    y_pos = 0.97
    for line, _ in summary_lines:
        weight = "bold" if not line.startswith(" ") and line else "normal"
        size = 9.5 if not line.startswith(" ") and line else 8.5
        ax.text(0.05, y_pos, line, transform=ax.transAxes,
                fontsize=size, color=_DARK, fontweight=weight,
                verticalalignment="top", fontfamily="monospace")
        y_pos -= 0.045

    ax.set_title("Key Metrics Summary", fontsize=11, fontweight="bold",
                 color=_DARK, pad=8)
    ax.set_facecolor(_LIGHT)


# ── Main dashboard ─────────────────────────────────────────────────────────────

def generate_full_dashboard(m: dict, output_dir: Path):
    fig = plt.figure(figsize=(18, 13), facecolor="white")
    fig.suptitle(
        "Forensic-Intel Platform — Accuracy & Performance Dashboard",
        fontsize=15, fontweight="bold", color=_DARK, y=0.98,
    )
    fig.text(
        0.5, 0.955,
        "Test data sourced from OTRF Security-Datasets, MITRE ATT&CK, "
        "Mandiant/CrowdStrike public TTPs",
        ha="center", fontsize=9, color=_GRAY, style="italic",
    )

    gs = GridSpec(2, 3, figure=fig, hspace=0.42, wspace=0.32,
                  top=0.93, bottom=0.06, left=0.06, right=0.97)

    _chart_component_overview(fig.add_subplot(gs[0, 0]), m)
    _chart_mitre_per_scenario(fig.add_subplot(gs[0, 1:3]), m)
    _chart_ioc_types(fig.add_subplot(gs[1, 0]), m)
    _chart_severity_scores(fig.add_subplot(gs[1, 1]), m)
    _chart_performance(fig.add_subplot(gs[0:, 2]) if False
                       else fig.add_subplot(gs[1, 2]), m)
    # Override last panel with summary table
    fig.get_axes()[-1].remove()
    ax_perf = fig.add_subplot(gs[1, 2])
    _chart_performance(ax_perf, m)

    # Add summary table as a floating text box
    ax_table = fig.add_axes([0.005, 0.0, 0.18, 0.48])
    _chart_summary_table(ax_table, m)

    path = output_dir / "stakeholder_accuracy_report.png"
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  Saved: {path}")
    return path


def generate_mitre_detail(m: dict, output_dir: Path):
    """Standalone detailed MITRE chart."""
    fig, ax = plt.subplots(figsize=(12, 5), facecolor="white")
    fig.suptitle("MITRE ATT&CK Detection — Detailed Breakdown",
                 fontsize=13, fontweight="bold", color=_DARK)
    _chart_mitre_per_scenario(ax, m)
    path = output_dir / "mitre_detection_detail.png"
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  Saved: {path}")
    return path


def generate_performance_chart(m: dict, output_dir: Path):
    """Standalone performance benchmark chart."""
    fig, ax = plt.subplots(figsize=(9, 4), facecolor="white")
    fig.suptitle("Analysis Engine Throughput", fontsize=13, fontweight="bold", color=_DARK)
    _chart_performance(ax, m)
    path = output_dir / "performance_benchmark.png"
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  Saved: {path}")
    return path


def generate_severity_chart(m: dict, output_dir: Path):
    """Standalone severity scoring chart."""
    fig, ax = plt.subplots(figsize=(10, 5), facecolor="white")
    fig.suptitle("Severity Scoring Accuracy by Scenario",
                 fontsize=13, fontweight="bold", color=_DARK)
    _chart_severity_scores(ax, m)
    path = output_dir / "severity_scoring.png"
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  Saved: {path}")
    return path


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    output_dir = Path(__file__).resolve().parent.parent / "reports"
    output_dir.mkdir(exist_ok=True)

    print("Collecting accuracy metrics (running analysis against test scenarios)...")
    m = collect_all_metrics()
    print("Done.\n")

    print("Generating charts:")
    generate_full_dashboard(m, output_dir)
    generate_mitre_detail(m, output_dir)
    generate_performance_chart(m, output_dir)
    generate_severity_chart(m, output_dir)

    print(f"\nAll charts written to: {output_dir.resolve()}")
    print("\nKey results:")
    print(f"  MITRE F1 (aggregate):  {m['mitre']['aggregate_attack_f1']:.0%}")
    print(f"  IOC recall:            {m['ioc']['recall']:.0%}")
    print(f"  Severity band acc:     {m['severity']['band_accuracy']:.0%}")
    print(f"  Attacker detected:     {'YES' if m['anomaly']['attacker_flagged'] else 'NO'}")
    print(f"  Svc account excluded:  {'YES' if m['anomaly']['svc_backup_excluded'] else 'NO'}")
    print(f"  MITRE throughput:      {m['performance']['mitre_mapper_eps']:,} eps")
