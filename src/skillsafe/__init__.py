"""SkillSafe — secured skill registry client for AI coding tools."""

from skillsafe._cli import VERSION as __version__
from skillsafe._cli import Scanner, SkillSafeClient, SkillSafeError, ScanError

__all__ = [
    "__version__",
    "Scanner",
    "SkillSafeClient",
    "SkillSafeError",
    "ScanError",
]
