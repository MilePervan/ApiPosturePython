"""Licensing context stub for Pro features."""

from dataclasses import dataclass
from enum import Enum


class LicenseType(str, Enum):
    """License type."""

    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class LicenseContext:
    """License context containing license information."""

    license_type: LicenseType = LicenseType.COMMUNITY
    is_valid: bool = True
    expiry_date: str | None = None
    features: list[str] | None = None

    @property
    def is_pro(self) -> bool:
        """Check if this is a Pro license."""
        return self.license_type in (LicenseType.PRO, LicenseType.ENTERPRISE)

    @property
    def is_enterprise(self) -> bool:
        """Check if this is an Enterprise license."""
        return self.license_type == LicenseType.ENTERPRISE
