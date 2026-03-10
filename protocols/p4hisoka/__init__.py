"""
Hisoka (C3) - Adaptive Deception
Real-time skill profiling + LLM-driven adaptive responses
"""
from .hisoka_deceptor import HisokaDeceptor
from .skill_classifier import HisokaSkillClassifier

__all__ = ["HisokaDeceptor", "HisokaSkillClassifier"]
