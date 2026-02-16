"""AI configuration validation utilities.

.. deprecated::
    Use :meth:`~netpal.services.ai.provider_factory.ProviderFactory.validate`
    directly instead.  This thin wrapper is kept only so existing imports
    continue to work; it will be removed in a future release.
"""
import warnings
from typing import Dict


class AIValidator:
    """Validates AI provider configuration.

    .. deprecated::
        Use ``ProviderFactory.validate(config)`` directly.
    """

    @classmethod
    def validate(cls, config: Dict) -> bool:
        """Validate AI configuration.

        Args:
            config: Configuration dictionary

        Returns:
            True if configuration is valid, False otherwise
        """
        warnings.warn(
            "AIValidator.validate() is deprecated. "
            "Use ProviderFactory.validate() directly.",
            DeprecationWarning,
            stacklevel=2,
        )
        from ..services.ai.provider_factory import ProviderFactory
        return ProviderFactory.validate(config)
