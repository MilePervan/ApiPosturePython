from dataclasses import dataclass
from typing import Literal


@dataclass
class AIFilterConfig:
    """Configuration for ApiPosture's AI false-positive filter."""

    use_llm: bool = True
    llm_model: str = "codellama"

    # Confidence values are percentages in the range 0..100.
    auto_suppress_threshold: int = 85
    high_confidence_threshold: int = 90

    use_rules: bool = True
    min_rule_support: int = 3

    # Interactive mode is the safer default while evaluating the filter.
    mode: Literal["automatic", "interactive", "disabled"] = "interactive"
    validate_rules_interactive: bool = True
    protect_critical: bool = True
    code_context_lines: int = 10
    dataset_path: str = "dataset.json"
    show_reasoning: bool = True
    verbose: bool = True

    def __post_init__(self) -> None:
        if not 0 <= self.auto_suppress_threshold <= 100:
            raise ValueError("auto_suppress_threshold must be between 0 and 100")
        if not 0 <= self.high_confidence_threshold <= 100:
            raise ValueError("high_confidence_threshold must be between 0 and 100")
        if self.min_rule_support < 1:
            raise ValueError("min_rule_support must be at least 1")
        if self.code_context_lines < 1:
            raise ValueError("code_context_lines must be at least 1")
        if self.mode not in {"automatic", "interactive", "disabled"}:
            raise ValueError(f"Unsupported AI filter mode: {self.mode}")

    @classmethod
    def automatic(cls) -> "AIFilterConfig":
        return cls(
            mode="automatic",
            auto_suppress_threshold=85,
            high_confidence_threshold=90,
            min_rule_support=3,
            validate_rules_interactive=False,
            protect_critical=True,
            verbose=False,
        )

    @classmethod
    def interactive(cls) -> "AIFilterConfig":
        return cls(
            mode="interactive",
            validate_rules_interactive=True,
            protect_critical=True,
            verbose=True,
            show_reasoning=True,
        )

    @classmethod
    def rules_review(cls) -> "AIFilterConfig":
        # Review candidate rules interactively; do not use the LLM to suppress findings.
        return cls(
            mode="automatic",
            use_llm=False,
            use_rules=True,
            validate_rules_interactive=True,
            protect_critical=True,
            verbose=True,
        )

    @classmethod
    def conservative(cls) -> "AIFilterConfig":
        return cls(
            mode="automatic",
            auto_suppress_threshold=95,
            high_confidence_threshold=95,
            min_rule_support=5,
            validate_rules_interactive=True,
            protect_critical=True,
            verbose=True,
        )

    @classmethod
    def disabled(cls) -> "AIFilterConfig":
        return cls(use_llm=False, use_rules=False, mode="disabled")

    @classmethod
    def from_dict(cls, data: dict | None) -> "AIFilterConfig":
        if not data:
            return cls.interactive()

        presets = {
            "automatic": cls.automatic,
            "interactive": cls.interactive,
            "conservative": cls.conservative,
            "disabled": cls.disabled,
            "rules_review": cls.rules_review,
        }

        preset_name = data.get("preset")
        if preset_name and preset_name not in presets:
            raise ValueError(f"Unknown AI filter preset: {preset_name}")

        config = presets[preset_name]() if preset_name else cls.interactive()

        known_fields = {
            "use_llm",
            "llm_model",
            "auto_suppress_threshold",
            "high_confidence_threshold",
            "use_rules",
            "min_rule_support",
            "mode",
            "code_context_lines",
            "dataset_path",
            "show_reasoning",
            "verbose",
            "validate_rules_interactive",
            "protect_critical",
        }

        for key, value in data.items():
            if key in known_fields:
                setattr(config, key, value)

        # Validate values after applying overrides from the dictionary.
        config.__post_init__()
        return config
