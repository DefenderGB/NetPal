"""Mode handlers for NetPal CLI.

This package contains mode-specific handlers that encapsulate
the workflow logic for different execution modes.

Subcommand handlers:
  - AssetCreateHandler  → netpal assets
  - ReconCLIHandler     → netpal recon
  - AIReviewHandler     → netpal ai-review
  - AIEnhanceHandler    → netpal ai-report-enhance
  - FindingsCLIHandler  → netpal findings
  - HostsHandler        → netpal hosts
  - PullHandler         → netpal pull
  - InitHandler         → netpal init
  - ListHandler         → netpal list
  - SetHandler          → netpal set
  - SetupHandler        → netpal setup
  - AutoHandler         → netpal auto
"""
from .base_handler import ModeHandler
from .asset_create_handler import AssetCreateHandler
from .recon_cli_handler import ReconCLIHandler
from .ai_review_handler import AIReviewHandler
from .ai_enhance_handler import AIEnhanceHandler
from .findings_cli_handler import FindingsCLIHandler
from .pull_handler import PullHandler
from .hosts_handler import HostsHandler
from .init_handler import InitHandler
from .list_handler import ListHandler
from .set_handler import SetHandler
from .setup_handler import SetupHandler
from .auto_handler import AutoHandler

__all__ = [
    'ModeHandler',
    'AssetCreateHandler',
    'ReconCLIHandler',
    'AIReviewHandler',
    'AIEnhanceHandler',
    'FindingsCLIHandler',
    'HostsHandler',
    'PullHandler',
    'InitHandler',
    'ListHandler',
    'SetHandler',
    'SetupHandler',
    'AutoHandler',
]
