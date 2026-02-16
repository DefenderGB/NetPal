"""Factory for creating Asset objects.

This module provides a factory pattern for creating Asset objects from
different sources, eliminating 156+ duplicate lines across cli.py.
"""
import os
from typing import Any


class AssetFactory:
    """Factory for creating different types of assets.
    
    This factory eliminates 4 duplicate asset creation blocks in cli.py,
    providing a single source of truth for asset object construction.
    
    Example:
        >>> from netpal.models.asset import Asset
        >>> factory = AssetFactory()
        >>> asset = factory.create_asset('network', 'DMZ Network', 0, '192.168.1.0/24')
        >>> asset.type
        'network'
        >>> asset.network
        '192.168.1.0/24'
    """
    
    @staticmethod
    def _write_targets_file(project_id: str, name: str, targets_csv: str) -> str:
        """Write comma-separated targets to a .txt file inside scan_results/.

        Args:
            project_id: Project UUID (used as directory name).
            name: Asset name (sanitised for use as filename).
            targets_csv: Comma-separated host list.

        Returns:
            Relative path (from scan_results/) to the created file.
        """
        from netpal.utils.persistence.file_utils import ensure_dir
        from netpal.utils.persistence.project_paths import get_base_scan_results_dir
        from netpal.utils.naming_utils import sanitize_for_filename

        base_dir = get_base_scan_results_dir()
        safe_name = sanitize_for_filename(name)
        targets_dir = os.path.join(base_dir, project_id)
        ensure_dir(targets_dir)

        filepath = os.path.join(targets_dir, f"{safe_name}_targets.txt")
        hosts = [h.strip() for h in targets_csv.split(',') if h.strip()]
        with open(filepath, 'w') as fh:
            fh.write('\n'.join(hosts) + '\n')

        # Return path relative to scan_results/ for portability
        return os.path.relpath(filepath, base_dir)

    @staticmethod
    def create_asset(
        asset_type: str, 
        name: str, 
        asset_id: int, 
        target_data: Any,
        project_id: str = '',
    ):
        """Create Asset object based on type.
        
        Args:
            asset_type: Type ('network', 'list', 'single')
            name: Asset name
            asset_id: Unique identifier
            target_data: Type-specific target data
            project_id: Project UUID (needed for list-type to write targets file)
            
        Returns:
            Asset object
            
        Raises:
            ValueError: If asset_type is not recognized
            
        Example:
            >>> asset = AssetFactory.create_asset(
            ...     'network', 'DMZ', 0, '192.168.1.0/24'
            ... )
            >>> asset.type
            'network'
        """
        from netpal.models.asset import Asset
        
        if asset_type == 'network':
            return Asset(
                asset_id=asset_id,
                asset_type='network',
                name=name,
                network=target_data
            )
        elif asset_type == 'list':
            # Handle both string and dict format for list assets
            if isinstance(target_data, dict):
                return Asset(
                    asset_id=asset_id,
                    asset_type='list',
                    name=name,
                    file=target_data.get('file', '')
                )
            else:
                # Comma-separated hosts → write to file
                file_path = AssetFactory._write_targets_file(
                    project_id, name, target_data
                )
                return Asset(
                    asset_id=asset_id,
                    asset_type='list',
                    name=name,
                    file=file_path
                )
        elif asset_type == 'single':
            return Asset(
                asset_id=asset_id,
                asset_type='single',
                name=name,
                target=target_data
            )
        else:
            raise ValueError(f"Unknown asset type: {asset_type}")
    
    @staticmethod
    def create_from_subcommand_args(args, project):
        """Create asset from the new subcommand-style CLI arguments.
        
        Maps the new subparser args (--range, --targets, --target, --file)
        to asset creation.
        
        Args:
            args: Parsed command-line arguments with attributes:
                  - type: Asset type ('network', 'list', 'single')
                  - name: Human-readable asset name
                  - range: CIDR range (network type)
                  - targets: Comma-separated targets or path to .txt file (list type)
                  - target: Single IP/hostname (single type)
                  - file: Path to host-list file (list type)
            project: Project object to get next asset_id from
            
        Returns:
            Asset object
            
        Raises:
            ValueError: If required arguments are missing
        """
        asset_id = len(project.assets)
        if args.type == 'network':
            if not getattr(args, 'range', None):
                raise ValueError("--range is required for network type")
            return AssetFactory.create_asset(
                'network', args.name, asset_id, args.range,
                project_id=project.project_id,
            )
        elif args.type == 'list':
            targets_val = getattr(args, 'targets', None)
            file_val = getattr(args, 'file', None)

            # If --targets points to a .txt file, treat it as --file
            if targets_val and targets_val.lower().endswith('.txt'):
                if not os.path.isfile(targets_val):
                    raise ValueError(f"File not found: {targets_val}")
                file_val = targets_val
                targets_val = None

            if file_val:
                return AssetFactory.create_asset(
                    'list', args.name, asset_id, {'file': file_val},
                    project_id=project.project_id,
                )
            elif targets_val:
                return AssetFactory.create_asset(
                    'list', args.name, asset_id, targets_val,
                    project_id=project.project_id,
                )
            else:
                raise ValueError("--targets or --file is required for list type")
        elif args.type == 'single':
            if not getattr(args, 'target', None):
                raise ValueError("--target is required for single type")
            return AssetFactory.create_asset(
                'single', args.name, asset_id, args.target,
                project_id=project.project_id,
            )
        else:
            raise ValueError(f"Unknown asset type: {args.type}")
