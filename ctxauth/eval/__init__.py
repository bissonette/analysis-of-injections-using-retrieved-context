"""Протокол оценки: метрики и прогон защит над размеченными наборами."""
from .metrics import DetectionMetrics, aggregate, detection_metrics
from .sample import AttackSample
from .harness import evaluate_defense, EvalReport

__all__ = ["DetectionMetrics", "aggregate", "detection_metrics",
           "AttackSample", "evaluate_defense", "EvalReport"]
