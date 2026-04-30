"""License manager stub for Pro features."""

from apiposture.core.licensing.context import LicenseContext


class LicenseManager:
    """Manages license activation and validation (stub)."""

    _instance: "LicenseManager | None" = None
    _context: LicenseContext

    def __new__(cls) -> "LicenseManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._context = LicenseContext()
        return cls._instance

    @property
    def context(self) -> LicenseContext:
        """Get the current license context."""
        return self._context

    def activate(self, key: str) -> tuple[bool, str]:
        """
        Activate a license key.

        Returns (success, message).
        """
        # Stub implementation - always returns community edition
        return False, "License activation is not available in the open-source version."

    def deactivate(self) -> tuple[bool, str]:
        """
        Deactivate the current license.

        Returns (success, message).
        """
        self._context = LicenseContext()
        return True, "License deactivated."

    def validate(self) -> bool:
        """Validate the current license."""
        return self._context.is_valid

    def get_status(self) -> dict[str, object]:
        """Get license status information."""
        return {
            "type": self._context.license_type.value,
            "valid": self._context.is_valid,
            "expiry": self._context.expiry_date,
            "features": self._context.features or [],
        }
