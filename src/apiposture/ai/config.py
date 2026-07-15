from dataclasses import dataclass
from typing import Literal


@dataclass
class AIFilterConfig:
    use_llm: bool = True
    llm_model: str = "codellama"
    auto_suppress_threshold: int = 70
    high_confidence_threshold: int = 85
    use_rules: bool = True
    min_rule_support: int = 2
    mode: Literal["automatic", "interactive", "disabled"] = "automatic"
    validate_rules_interactive: bool = False
    protect_critical: bool = True
    code_context_lines: int = 10
    dataset_path: str = "dataset.json"
    show_reasoning: bool = True
    verbose: bool = True

    @classmethod
    def automatic(cls) -> "AIFilterConfig":
        return cls(use_llm=True, mode="automatic", auto_suppress_threshold=70, verbose=False)

    @classmethod
    def interactive(cls) -> "AIFilterConfig":
        return cls(use_llm=True, mode="interactive", verbose=True, show_reasoning=True,
                   validate_rules_interactive=True)

    @classmethod
    def rules_review(cls) -> "AIFilterConfig":
        
        return cls(use_llm=True, mode="automatic", auto_suppress_threshold=70,
                   validate_rules_interactive=True, verbose=True)

    @classmethod
    def conservative(cls) -> "AIFilterConfig":
        return cls(use_llm=True, mode="automatic", auto_suppress_threshold=90, min_rule_support=3, verbose=True)

    @classmethod
    def disabled(cls) -> "AIFilterConfig":
        return cls(use_llm=False, use_rules=False, mode="disabled")

    @classmethod
    def from_dict(cls, data: dict | None) -> "AIFilterConfig":
        
        if not data:
            return cls.automatic()

        preset_name = data.get("preset")
        presets = {
            "automatic": cls.automatic,
            "interactive": cls.interactive,
            "conservative": cls.conservative,
            "disabled": cls.disabled,
            "rules_review": cls.rules_review,
        }
        config = presets.get(preset_name, cls)() if preset_name else cls()

        known_fields = {
            "use_llm", "llm_model", "auto_suppress_threshold",
            "high_confidence_threshold", "use_rules", "min_rule_support",
            "mode", "code_context_lines", "dataset_path",
            "show_reasoning", "verbose", "validate_rules_interactive",
            "protect_critical",
        }
        for key, value in data.items():
            if key in known_fields:
                setattr(config, key, value)

        return config