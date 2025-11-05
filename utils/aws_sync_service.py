"""
AWS Sync Service for NetPal.

This module provides synchronization between local storage (JSON files, scan results)
and AWS cloud storage (DynamoDB tables, S3 bucket).

Features:
- Bidirectional sync for project files with DynamoDB
- Bidirectional sync for states file with DynamoDB
- Bidirectional sync for scan_results directory with S3
- Online/offline mode support
- Automatic table creation and verification
"""

import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import threading

from utils.constants import (
    get_sync_aws_profile,
    get_sync_aws_region,
    get_sync_dynamodb_projects_table,
    get_sync_dynamodb_states_table,
    get_sync_s3_bucket,
    PROJECTS_DIR,
    STATES_FILE,
    SCAN_RESULTS_DIR
)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class AwsSyncService:
    """
    Manages synchronization between local storage and AWS services.
    
    This service handles:
    - DynamoDB sync for projects and states
    - S3 sync for scan results
    - Table creation and verification
    - Error handling and retry logic
    """
    
    # AWS Configuration (loaded from sync_settings.yaml via constants)
    @property
    def PROFILE_NAME(self):
        """Get AWS profile name from configuration."""
        return get_sync_aws_profile()
    
    @property
    def REGION_NAME(self):
        """Get AWS region from configuration."""
        return get_sync_aws_region()
    
    @property
    def PROJECTS_TABLE(self):
        """Get DynamoDB projects table name from configuration."""
        return get_sync_dynamodb_projects_table()
    
    @property
    def STATES_TABLE(self):
        """Get DynamoDB states table name from configuration."""
        return get_sync_dynamodb_states_table()
    
    @property
    def S3_BUCKET(self):
        """Get S3 bucket name from configuration."""
        return get_sync_s3_bucket()
    
    # Local paths (loaded from constants)
    PROJECTS_DIR = Path(PROJECTS_DIR)
    STATES_FILE = Path(STATES_FILE)
    SCAN_RESULTS_DIR = Path(SCAN_RESULTS_DIR)
    
    # Files to exclude from S3 sync (system and repository metadata files)
    EXCLUDED_FILES = {'.DS_Store', '.gitkeep'}
    
    def __init__(self, enabled: bool = True):
        """
        Initialize the AWS sync service.
        
        Args:
            enabled: Whether sync is enabled (online mode)
        """
        self.enabled = enabled
        self.lock = threading.Lock()
        self.last_sync_time = 0
        
        # Initialize boto3 clients if enabled and available
        self.dynamodb = None
        self.dynamodb_client = None
        self.s3 = None
        self.s3_client = None
        
        if self.enabled and BOTO3_AVAILABLE:
            try:
                self._initialize_clients()
            except Exception as e:
                print(f"Failed to initialize AWS clients: {e}")
                self.enabled = False
    
    def _initialize_clients(self):
        """Initialize boto3 clients with the AWS profile."""
        try:
            # Create session with AWS profile
            session = boto3.Session(
                profile_name=self.PROFILE_NAME,
                region_name=self.REGION_NAME
            )
            
            # Initialize DynamoDB
            self.dynamodb = session.resource('dynamodb')
            self.dynamodb_client = session.client('dynamodb')
            
            # Initialize S3
            self.s3 = session.resource('s3')
            self.s3_client = session.client('s3')
            
            print(f"✓ AWS clients initialized with profile '{self.PROFILE_NAME}' in {self.REGION_NAME}")
            
        except (ProfileNotFound, NoCredentialsError) as e:
            print(f"AWS profile '{self.PROFILE_NAME}' not found or invalid credentials: {e}")
            raise
        except Exception as e:
            print(f"Error initializing AWS clients: {e}")
            raise
    
    def is_enabled(self) -> bool:
        """Check if sync service is enabled and ready."""
        return self.enabled and self.dynamodb is not None and self.s3 is not None
    
    def check_aws_connectivity(self) -> bool:
        """
        Check if AWS credentials are valid and can connect to AWS services.
        Tests connectivity by calling STS get_caller_identity.
        
        Returns:
            True if AWS is accessible and credentials are valid, False otherwise
        """
        if not BOTO3_AVAILABLE:
            return False
        
        try:
            # Create session with AWS profile
            session = boto3.Session(
                profile_name=self.PROFILE_NAME,
                region_name=self.REGION_NAME
            )
            
            # Try to get caller identity - this is a lightweight call that verifies credentials
            sts_client = session.client('sts')
            response = sts_client.get_caller_identity()
            
            # If we got here, credentials are valid
            return True
            
        except (ProfileNotFound, NoCredentialsError) as e:
            # Profile or credentials not found
            return False
        except Exception as e:
            # Any other error (network, timeout, etc.)
            return False
    
    # ========================================================================
    # DynamoDB Table Management
    # ========================================================================
    
    def verify_or_create_tables(self) -> bool:
        """
        Verify DynamoDB tables exist, create them if they don't.
        
        Returns:
            True if tables exist or were created successfully
        """
        if not self.is_enabled():
            return False
        
        try:
            # Verify/create projects table
            if not self._table_exists(self.PROJECTS_TABLE):
                print(f"Creating DynamoDB table: {self.PROJECTS_TABLE}")
                self._create_projects_table()
            
            # Verify/create states table
            if not self._table_exists(self.STATES_TABLE):
                print(f"Creating DynamoDB table: {self.STATES_TABLE}")
                self._create_states_table()
            
            return True
            
        except Exception as e:
            print(f"Error verifying/creating tables: {e}")
            return False
    
    def _table_exists(self, table_name: str) -> bool:
        """Check if a DynamoDB table exists."""
        try:
            self.dynamodb_client.describe_table(TableName=table_name)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False
            raise
    
    def _create_projects_table(self):
        """Create the projects DynamoDB table."""
        table = self.dynamodb.create_table(
            TableName=self.PROJECTS_TABLE,
            KeySchema=[
                {
                    'AttributeName': 'project_name',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'project_name',
                    'AttributeType': 'S'
                }
            ],
            BillingMode='PAY_PER_REQUEST'  # On-demand billing
        )
        
        # Wait for table to be created
        table.meta.client.get_waiter('table_exists').wait(TableName=self.PROJECTS_TABLE)
        print(f"✓ Created DynamoDB table: {self.PROJECTS_TABLE}")
    
    def _create_states_table(self):
        """Create the states DynamoDB table."""
        table = self.dynamodb.create_table(
            TableName=self.STATES_TABLE,
            KeySchema=[
                {
                    'AttributeName': 'timestamp',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'timestamp',
                    'AttributeType': 'N'
                }
            ],
            BillingMode='PAY_PER_REQUEST'  # On-demand billing
        )
        
        # Wait for table to be created
        table.meta.client.get_waiter('table_exists').wait(TableName=self.STATES_TABLE)
        print(f"✓ Created DynamoDB table: {self.STATES_TABLE}")
    
    # ========================================================================
    # Project Name Normalization
    # ========================================================================
    
    @staticmethod
    def normalize_project_name(name: str) -> str:
        """
        Normalize project name to lowercase with underscores.
        
        Args:
            name: Original project name
            
        Returns:
            Normalized name (lowercase, spaces→underscores, trimmed)
            
        Examples:
            >>> normalize_project_name("My Project ")
            "my_project"
            >>> normalize_project_name("Test-Project")
            "test-project"
        """
        # Strip whitespace
        normalized = name.strip()
        # Replace spaces with underscores
        normalized = normalized.replace(' ', '_')
        # Convert to lowercase
        normalized = normalized.lower()
        return normalized
    
    # ========================================================================
    # Projects Sync (DynamoDB)
    # ========================================================================
    
    def sync_current_project_bidirectional(self, current_project_name: str) -> Dict[str, Any]:
        """
        Bidirectionally sync the current project with DynamoDB using timestamp comparison.
        
        Respects the 'sync_to_cloud' flag - projects marked as local-only will not be synced.
        
        Compares 'last_modified_epoch' (local) with 'last_update_epoch_time' (DynamoDB).
        - If local is newer: uploads local data to DynamoDB
        - If DynamoDB is newer: downloads and overwrites local file
        - If equal: no sync needed
        
        Args:
            current_project_name: Name of the current project
            
        Returns:
            Dictionary with sync details: {
                'action': 'uploaded'|'downloaded'|'no_sync'|'skipped'|'error',
                'message': str
            }
        """
        if not self.is_enabled():
            return {'action': 'error', 'message': 'Sync service not enabled'}
        
        try:
            normalized_name = self.normalize_project_name(current_project_name)
            table = self.dynamodb.Table(self.PROJECTS_TABLE)
            
            # Get local project data and timestamp
            local_filepath = self.PROJECTS_DIR / f"{normalized_name}.json"
            local_timestamp = None
            local_data = None
            
            if local_filepath.exists():
                with open(local_filepath, 'r', encoding='utf-8') as f:
                    local_data = json.load(f)
                
                # Check if project should be synced to cloud (default True for backward compatibility)
                # Check both long form 'sync_to_cloud' and short form 'sync' (from to_dict optimization)
                sync_to_cloud = local_data.get('sync_to_cloud')
                if sync_to_cloud is None:
                    # Check short form 'sync' (0 = False, 1 = True)
                    sync_value = local_data.get('sync')
                    if sync_value is not None:
                        sync_to_cloud = bool(sync_value)
                    else:
                        sync_to_cloud = True  # Default for backward compatibility
                
                if not sync_to_cloud:
                    return {'action': 'skipped', 'message': 'Project marked as local-only (sync_to_cloud=False)'}
                
                # Handle both old and new field names (last_modified_epoch and mod_ts)
                local_timestamp = local_data.get('mod_ts', local_data.get('last_modified_epoch', 0))
            
            # Get DynamoDB data and timestamp
            dynamodb_timestamp = None
            dynamodb_data = None
            
            try:
                response = table.get_item(Key={'project_name': normalized_name})
                if 'Item' in response:
                    item = response['Item']
                    dynamodb_timestamp = item.get('last_update_epoch_time', 0)
                    json_data_str = item.get('json_data')
                    if json_data_str:
                        dynamodb_data = json.loads(json_data_str)
            except Exception as e:
                print(f"Error fetching project from DynamoDB: {e}")
            
            # Determine sync direction based on timestamps
            if local_data is None and dynamodb_data is None:
                return {'action': 'no_sync', 'message': 'Project does not exist locally or in DynamoDB'}
            
            elif local_data is None:
                # Only exists in DynamoDB - download
                self.PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
                with open(local_filepath, 'w', encoding='utf-8') as f:
                    json.dump(dynamodb_data, f, indent=2, ensure_ascii=False)
                return {'action': 'downloaded', 'message': f'Downloaded from DynamoDB (local did not exist)'}
            
            elif dynamodb_data is None:
                # Only exists locally - upload
                table.put_item(
                    Item={
                        'project_name': normalized_name,
                        'last_update_epoch_time': local_timestamp,
                        'json_data': json.dumps(local_data)
                    }
                )
                return {'action': 'uploaded', 'message': f'Uploaded to DynamoDB (DynamoDB did not exist)'}
            
            else:
                # Both exist - compare timestamps
                if local_timestamp > dynamodb_timestamp:
                    # Local is newer - upload
                    table.put_item(
                        Item={
                            'project_name': normalized_name,
                            'last_update_epoch_time': local_timestamp,
                            'json_data': json.dumps(local_data)
                        }
                    )
                    return {'action': 'uploaded', 'message': f'Uploaded to DynamoDB (local newer: {local_timestamp} > {dynamodb_timestamp})'}
                
                elif dynamodb_timestamp > local_timestamp:
                    # DynamoDB is newer - download
                    with open(local_filepath, 'w', encoding='utf-8') as f:
                        json.dump(dynamodb_data, f, indent=2, ensure_ascii=False)
                    return {'action': 'downloaded', 'message': f'Downloaded from DynamoDB (DynamoDB newer: {dynamodb_timestamp} > {local_timestamp})'}
                
                else:
                    # Equal timestamps - no sync needed
                    return {'action': 'no_sync', 'message': f'No sync needed (equal timestamps: {local_timestamp})'}
        
        except Exception as e:
            return {'action': 'error', 'message': f'Error during bidirectional sync: {e}'}
    
    def sync_projects_to_dynamodb(self, exclude_project: Optional[str] = None) -> Tuple[int, int]:
        """
        Sync local project files to DynamoDB.
        
        Args:
            exclude_project: Optional project name to exclude from sync
        
        Returns:
            Tuple of (uploaded_count, error_count)
        """
        if not self.is_enabled():
            return 0, 0
        
        uploaded = 0
        errors = 0
        
        # Normalize exclude_project if provided
        exclude_normalized = None
        if exclude_project:
            exclude_normalized = self.normalize_project_name(exclude_project)
        
        try:
            table = self.dynamodb.Table(self.PROJECTS_TABLE)
            
            # Iterate through all project JSON files
            for project_file in self.PROJECTS_DIR.glob("*.json"):
                try:
                    # Read project data
                    with open(project_file, 'r', encoding='utf-8') as f:
                        project_data = json.load(f)
                    
                    # Check if project should be synced to cloud (default True for backward compatibility)
                    # Check both long form 'sync_to_cloud' and short form 'sync' (from to_dict optimization)
                    sync_to_cloud = project_data.get('sync_to_cloud')
                    if sync_to_cloud is None:
                        # Check short form 'sync' (0 = False, 1 = True)
                        sync_value = project_data.get('sync')
                        if sync_value is not None:
                            sync_to_cloud = bool(sync_value)
                        else:
                            sync_to_cloud = True  # Default for backward compatibility
                    
                    if not sync_to_cloud:
                        # Skip projects that are marked as local-only
                        continue
                    
                    # Get and normalize project name
                    project_name = project_data.get('name', project_file.stem)
                    normalized_name = self.normalize_project_name(project_name)
                    
                    # Skip if this is the excluded project
                    if exclude_normalized and normalized_name == exclude_normalized:
                        continue
                    
                    # Get last modified time from project data (handle both old and new field names)
                    last_modified = project_data.get('mod_ts', project_data.get('last_modified_epoch', int(time.time())))
                    
                    # Upload to DynamoDB
                    table.put_item(
                        Item={
                            'project_name': normalized_name,
                            'last_update_epoch_time': last_modified,
                            'json_data': json.dumps(project_data)
                        }
                    )
                    uploaded += 1
                    
                except Exception as e:
                    print(f"Error uploading project {project_file.name}: {e}")
                    errors += 1
            
            return uploaded, errors
            
        except Exception as e:
            print(f"Error syncing projects to DynamoDB: {e}")
            return uploaded, errors
    
    def sync_projects_from_dynamodb(self, exclude_project: Optional[str] = None) -> Tuple[int, int]:
        """
        Sync projects from DynamoDB to local files.
        
        Args:
            exclude_project: Optional project name to exclude from sync
        
        Returns:
            Tuple of (downloaded_count, error_count)
        """
        if not self.is_enabled():
            return 0, 0
        
        downloaded = 0
        errors = 0
        
        # Normalize exclude_project if provided
        exclude_normalized = None
        if exclude_project:
            exclude_normalized = self.normalize_project_name(exclude_project)
        
        try:
            table = self.dynamodb.Table(self.PROJECTS_TABLE)
            
            # Scan all items from DynamoDB
            response = table.scan()
            items = response.get('Items', [])
            
            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                items.extend(response.get('Items', []))
            
            # Process each project
            for item in items:
                try:
                    project_name = item.get('project_name')
                    json_data_str = item.get('json_data')
                    
                    if not project_name or not json_data_str:
                        continue
                    
                    # Skip if this is the excluded project
                    if exclude_normalized and project_name == exclude_normalized:
                        continue
                    
                    # Parse JSON data
                    project_data = json.loads(json_data_str)
                    
                    # Create filename (normalized name)
                    filename = f"{project_name}.json"
                    filepath = self.PROJECTS_DIR / filename
                    
                    # Write to local file
                    self.PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(project_data, f, indent=2, ensure_ascii=False)
                    
                    downloaded += 1
                    
                except Exception as e:
                    print(f"Error downloading project {project_name}: {e}")
                    errors += 1
            
            return downloaded, errors
            
        except Exception as e:
            print(f"Error syncing projects from DynamoDB: {e}")
            return downloaded, errors
    
    # ========================================================================
    # States Sync (DynamoDB)
    # ========================================================================
    
    def sync_states_to_dynamodb(self) -> bool:
        """
        Sync local states.json to DynamoDB.
        Maintains only one entry in the table by deleting all previous entries.
        
        Returns:
            True if successful
        """
        if not self.is_enabled():
            return False
        
        try:
            # Read states file
            if not self.STATES_FILE.exists():
                print("States file doesn't exist, skipping upload")
                return False
            
            with open(self.STATES_FILE, 'r', encoding='utf-8') as f:
                states_data = json.load(f)
            
            table = self.dynamodb.Table(self.STATES_TABLE)
            
            # Delete all existing items first to maintain single row
            try:
                response = table.scan()
                items = response.get('Items', [])
                
                # Delete all existing items
                with table.batch_writer() as batch:
                    for item in items:
                        batch.delete_item(Key={'timestamp': item['timestamp']})
                
                # Handle pagination if there are many items
                while 'LastEvaluatedKey' in response:
                    response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                    items = response.get('Items', [])
                    with table.batch_writer() as batch:
                        for item in items:
                            batch.delete_item(Key={'timestamp': item['timestamp']})
                
            except Exception as e:
                print(f"Warning: Error deleting old states entries: {e}")
                # Continue anyway to add the new entry
            
            # Add new entry with current timestamp
            current_time = int(time.time())
            table.put_item(
                Item={
                    'timestamp': current_time,
                    'json_data': json.dumps(states_data)
                }
            )
            
            return True
            
        except Exception as e:
            print(f"Error syncing states to DynamoDB: {e}")
            return False
    
    def sync_states_from_dynamodb(self) -> bool:
        """
        Sync states from DynamoDB to local states.json.
        Gets the most recent state entry.
        
        Returns:
            True if successful
        """
        if not self.is_enabled():
            return False
        
        try:
            table = self.dynamodb.Table(self.STATES_TABLE)
            
            # Scan to get all items (should be just one or a few)
            response = table.scan()
            items = response.get('Items', [])
            
            if not items:
                print("No states found in DynamoDB")
                return False
            
            # Get the most recent item
            latest_item = max(items, key=lambda x: x.get('timestamp', 0))
            json_data_str = latest_item.get('json_data')
            
            if not json_data_str:
                print("No json_data in states item")
                return False
            
            # Parse and write to local file
            states_data = json.loads(json_data_str)
            
            self.STATES_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.STATES_FILE, 'w', encoding='utf-8') as f:
                json.dump(states_data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"Error syncing states from DynamoDB: {e}")
            return False
    
    # ========================================================================
    # S3 Sync (Scan Results)
    # ========================================================================
    
    def _get_non_syncing_projects(self) -> set:
        """
        Get a set of normalized project names that should NOT be synced to cloud.
        
        Returns:
            Set of normalized project names with sync_to_cloud=False
        """
        non_syncing = set()
        
        try:
            # Read all project files to check sync_to_cloud status
            for project_file in self.PROJECTS_DIR.glob("*.json"):
                try:
                    with open(project_file, 'r', encoding='utf-8') as f:
                        project_data = json.load(f)
                    
                    # Check sync_to_cloud flag (default True for backward compatibility)
                    # Check both long form 'sync_to_cloud' and short form 'sync' (from to_dict optimization)
                    sync_to_cloud = project_data.get('sync_to_cloud')
                    if sync_to_cloud is None:
                        # Check short form 'sync' (0 = False, 1 = True)
                        sync_value = project_data.get('sync')
                        if sync_value is not None:
                            sync_to_cloud = bool(sync_value)
                        else:
                            sync_to_cloud = True  # Default for backward compatibility
                    
                    if not sync_to_cloud:
                        # Get normalized project name
                        project_name = project_data.get('name', project_file.stem)
                        normalized_name = self.normalize_project_name(project_name)
                        non_syncing.add(normalized_name)
                        
                except Exception as e:
                    print(f"Error reading project {project_file.name}: {e}")
                    
        except Exception as e:
            print(f"Error getting non-syncing projects: {e}")
        
        return non_syncing
    
    def sync_scan_results_to_s3(self, current_project_only: Optional[str] = None) -> Tuple[int, int]:
        """
        Upload scan results from local directory to S3.
        
        Args:
            current_project_only: If provided, only sync resources for this project
        
        Returns:
            Tuple of (uploaded_count, error_count)
        """
        if not self.is_enabled():
            return 0, 0
        
        uploaded = 0
        errors = 0
        
        # Normalize current_project_only if provided
        current_project_normalized = None
        if current_project_only:
            current_project_normalized = self.normalize_project_name(current_project_only)
        
        try:
            # Get list of files in S3
            s3_files = self._list_s3_files()
            
            # Get projects that should NOT be synced
            non_syncing_projects = self._get_non_syncing_projects()
            
            # Walk through local scan_results directory
            if not self.SCAN_RESULTS_DIR.exists():
                return 0, 0
            
            for root, dirs, files in os.walk(self.SCAN_RESULTS_DIR):
                for file in files:
                    try:
                        # Skip excluded files (.DS_Store, .gitkeep, etc.)
                        if file in self.EXCLUDED_FILES:
                            continue
                        
                        local_path = Path(root) / file
                        # Get relative path from scan_results directory
                        relative_path = local_path.relative_to(self.SCAN_RESULTS_DIR)
                        s3_key = str(relative_path).replace('\\', '/')  # Ensure forward slashes
                        
                        # Extract project name from path (first directory in relative path)
                        path_parts = relative_path.parts
                        if not path_parts:
                            continue
                        
                        project_name = path_parts[0]
                        
                        # If current_project_only is set, skip files not belonging to current project
                        if current_project_normalized and project_name != current_project_normalized:
                            continue
                        
                        # Check if this file belongs to a non-syncing project
                        if project_name in non_syncing_projects:
                            # Skip files for projects with sync_to_cloud=False
                            continue
                        
                        # Check if file exists in S3
                        if s3_key not in s3_files:
                            # Upload to S3
                            self.s3_client.upload_file(
                                str(local_path),
                                self.S3_BUCKET,
                                s3_key
                            )
                            uploaded += 1
                        
                    except Exception as e:
                        print(f"Error uploading {file}: {e}")
                        errors += 1
            
            return uploaded, errors
            
        except Exception as e:
            print(f"Error syncing to S3: {e}")
            return uploaded, errors
    
    def sync_scan_results_from_s3(self, current_project_only: Optional[str] = None) -> Tuple[int, int]:
        """
        Download scan results from S3 to local directory.
        
        Args:
            current_project_only: If provided, only sync resources for this project
        
        Returns:
            Tuple of (downloaded_count, error_count)
        """
        if not self.is_enabled():
            return 0, 0
        
        downloaded = 0
        errors = 0
        
        # Normalize current_project_only if provided
        current_project_normalized = None
        if current_project_only:
            current_project_normalized = self.normalize_project_name(current_project_only)
        
        try:
            # Get list of local files
            local_files = set()
            if self.SCAN_RESULTS_DIR.exists():
                for root, dirs, files in os.walk(self.SCAN_RESULTS_DIR):
                    for file in files:
                        local_path = Path(root) / file
                        relative_path = local_path.relative_to(self.SCAN_RESULTS_DIR)
                        local_files.add(str(relative_path).replace('\\', '/'))
            
            # Get projects that should NOT be synced
            non_syncing_projects = self._get_non_syncing_projects()
            
            # List objects in S3 bucket (filtered by prefix if current_project_only)
            paginator = self.s3_client.get_paginator('list_objects_v2')
            
            if current_project_normalized:
                # Only list objects for the current project
                pages = paginator.paginate(
                    Bucket=self.S3_BUCKET,
                    Prefix=f"{current_project_normalized}/"
                )
            else:
                # List all objects
                pages = paginator.paginate(Bucket=self.S3_BUCKET)
            
            for page in pages:
                for obj in page.get('Contents', []):
                    try:
                        s3_key = obj['Key']
                        
                        # Skip excluded files (.DS_Store, .gitkeep, etc.)
                        filename = s3_key.split('/')[-1]  # Get filename from path
                        if filename in self.EXCLUDED_FILES:
                            continue
                        
                        # Extract project name from S3 key (first part of path)
                        key_parts = s3_key.split('/')
                        if not key_parts:
                            continue
                        
                        project_name = key_parts[0]
                        
                        # If current_project_only is set, verify this file belongs to current project
                        if current_project_normalized and project_name != current_project_normalized:
                            continue
                        
                        # Check if this file belongs to a non-syncing project
                        if project_name in non_syncing_projects:
                            # Skip files for projects with sync_to_cloud=False
                            continue
                        
                        # Skip if file exists locally
                        if s3_key in local_files:
                            continue
                        
                        # Download from S3
                        local_path = self.SCAN_RESULTS_DIR / s3_key
                        local_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        self.s3_client.download_file(
                            self.S3_BUCKET,
                            s3_key,
                            str(local_path)
                        )
                        downloaded += 1
                        
                    except Exception as e:
                        print(f"Error downloading {s3_key}: {e}")
                        errors += 1
            
            return downloaded, errors
            
        except Exception as e:
            print(f"Error syncing from S3: {e}")
            return downloaded, errors
    
    def _list_s3_files(self) -> set:
        """
        Get a set of all file keys in the S3 bucket.
        
        Returns:
            Set of S3 object keys
        """
        s3_files = set()
        
        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.S3_BUCKET)
            
            for page in pages:
                for obj in page.get('Contents', []):
                    s3_files.add(obj['Key'])
            
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucket':
                raise
        
        return s3_files
    
    # ========================================================================
    # Deletion Operations
    # ========================================================================
    
    def delete_project_from_dynamodb(self, project_name: str) -> bool:
        """
        Delete a project from DynamoDB.
        
        Args:
            project_name: Name of the project to delete (will be normalized)
            
        Returns:
            True if successful or project doesn't exist, False on error
        """
        if not self.is_enabled():
            return False
        
        try:
            # Normalize project name to match DynamoDB key
            normalized_name = self.normalize_project_name(project_name)
            
            table = self.dynamodb.Table(self.PROJECTS_TABLE)
            
            # Delete the item
            table.delete_item(
                Key={'project_name': normalized_name}
            )
            
            print(f"[INFO] Deleted project '{normalized_name}' from DynamoDB table: {self.PROJECTS_TABLE}")
            return True
            
        except Exception as e:
            print(f"Error deleting project from DynamoDB: {e}")
            return False
    
    def delete_scan_results_from_s3(self, project_name: str) -> Tuple[int, int]:
        """
        Delete all scan results for a project from S3.
        
        Args:
            project_name: Name of the project whose scan results to delete
            
        Returns:
            Tuple of (deleted_count, error_count)
        """
        if not self.is_enabled():
            return 0, 0
        
        deleted = 0
        errors = 0
        
        try:
            # Normalize project name to match S3 directory structure
            normalized_name = self.normalize_project_name(project_name)
            
            # List all objects with this project prefix
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=self.S3_BUCKET,
                Prefix=f"{normalized_name}/"
            )
            
            # Collect all keys to delete
            objects_to_delete = []
            for page in pages:
                for obj in page.get('Contents', []):
                    objects_to_delete.append({'Key': obj['Key']})
            
            # Delete in batches (S3 allows up to 1000 objects per delete request)
            if objects_to_delete:
                for i in range(0, len(objects_to_delete), 1000):
                    batch = objects_to_delete[i:i+1000]
                    try:
                        response = self.s3_client.delete_objects(
                            Bucket=self.S3_BUCKET,
                            Delete={'Objects': batch}
                        )
                        deleted += len(response.get('Deleted', []))
                        errors += len(response.get('Errors', []))
                    except Exception as e:
                        print(f"Error deleting batch from S3: {e}")
                        errors += len(batch)
                
                print(f"[INFO] Deleted {deleted} file(s) for project '{normalized_name}' from S3 bucket: {self.S3_BUCKET}")
            else:
                print(f"[INFO] No scan results found in S3 for project '{normalized_name}'")
            
            return deleted, errors
            
        except Exception as e:
            print(f"Error deleting scan results from S3: {e}")
            return deleted, errors
    
    def delete_network_scan_results_from_s3(self, project_name: str, network_range: str) -> Tuple[int, int]:
        """
        Delete scan results for a specific network from S3.
        
        Args:
            project_name: Name of the project
            network_range: Network range (will be normalized)
            
        Returns:
            Tuple of (deleted_count, error_count)
        """
        if not self.is_enabled():
            return 0, 0
        
        deleted = 0
        errors = 0
        
        try:
            from utils.path_utils import sanitize_network_range
            
            # Normalize names to match S3 directory structure
            normalized_project = self.normalize_project_name(project_name)
            normalized_network = sanitize_network_range(network_range)
            
            # Construct the prefix for this network
            prefix = f"{normalized_project}/{normalized_network}/"
            
            # List all objects with this prefix
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=self.S3_BUCKET,
                Prefix=prefix
            )
            
            # Collect all keys to delete
            objects_to_delete = []
            for page in pages:
                for obj in page.get('Contents', []):
                    objects_to_delete.append({'Key': obj['Key']})
            
            # Delete in batches
            if objects_to_delete:
                for i in range(0, len(objects_to_delete), 1000):
                    batch = objects_to_delete[i:i+1000]
                    try:
                        response = self.s3_client.delete_objects(
                            Bucket=self.S3_BUCKET,
                            Delete={'Objects': batch}
                        )
                        deleted += len(response.get('Deleted', []))
                        errors += len(response.get('Errors', []))
                    except Exception as e:
                        print(f"Error deleting network batch from S3: {e}")
                        errors += len(batch)
                
                print(f"[INFO] Deleted {deleted} file(s) for network '{network_range}' from S3")
            else:
                print(f"[INFO] No scan results found in S3 for network '{network_range}'")
            
            return deleted, errors
            
        except Exception as e:
            print(f"Error deleting network scan results from S3: {e}")
            return deleted, errors
    
    # ========================================================================
    # Full Sync Operations
    # ========================================================================
    
    def perform_full_sync(self, current_project: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform a complete bidirectional sync of all data.
        
        Args:
            current_project: Optional current project name for project-scoped syncing.
                           If provided, uses enhanced sync logic:
                           - Current project: bidirectional with timestamp comparison
                           - Other projects: download all except current
                           - S3: sync only current project resources
        
        Returns:
            Dictionary with sync statistics
        """
        if not self.is_enabled():
            return {
                'enabled': False,
                'message': 'Sync service not enabled'
            }
        
        with self.lock:
            start_time = time.time()
            results = {
                'enabled': True,
                'timestamp': start_time,
                'current_project': current_project,
                'projects': {},
                'states': {},
                's3': {}
            }
            
            try:
                # Verify tables exist
                self.verify_or_create_tables()
                
                if current_project:
                    # Enhanced sync with current project context
                    
                    # 1. Sync current project bidirectionally with timestamp comparison
                    current_result = self.sync_current_project_bidirectional(current_project)
                    results['projects']['current_project'] = current_result
                    
                    # 2. Sync other projects (exclude current from both directions)
                    up_count, up_errors = self.sync_projects_to_dynamodb(exclude_project=current_project)
                    results['projects']['other_uploaded'] = up_count
                    results['projects']['other_upload_errors'] = up_errors
                    
                    down_count, down_errors = self.sync_projects_from_dynamodb(exclude_project=current_project)
                    results['projects']['other_downloaded'] = down_count
                    results['projects']['other_download_errors'] = down_errors
                    
                    # 3. Sync S3 for current project only
                    s3_up_count, s3_up_errors = self.sync_scan_results_to_s3(current_project_only=current_project)
                    results['s3']['uploaded'] = s3_up_count
                    results['s3']['upload_errors'] = s3_up_errors
                    
                    s3_down_count, s3_down_errors = self.sync_scan_results_from_s3(current_project_only=current_project)
                    results['s3']['downloaded'] = s3_down_count
                    results['s3']['download_errors'] = s3_down_errors
                    
                else:
                    # Legacy sync - all projects
                    
                    # Sync projects (bidirectional)
                    up_count, up_errors = self.sync_projects_to_dynamodb()
                    results['projects']['uploaded'] = up_count
                    results['projects']['upload_errors'] = up_errors
                    
                    down_count, down_errors = self.sync_projects_from_dynamodb()
                    results['projects']['downloaded'] = down_count
                    results['projects']['download_errors'] = down_errors
                    
                    # Sync S3 (bidirectional, all projects)
                    s3_up_count, s3_up_errors = self.sync_scan_results_to_s3()
                    results['s3']['uploaded'] = s3_up_count
                    results['s3']['upload_errors'] = s3_up_errors
                    
                    s3_down_count, s3_down_errors = self.sync_scan_results_from_s3()
                    results['s3']['downloaded'] = s3_down_count
                    results['s3']['download_errors'] = s3_down_errors
                
                # Sync states (always bidirectional, not project-specific)
                results['states']['uploaded'] = self.sync_states_to_dynamodb()
                results['states']['downloaded'] = self.sync_states_from_dynamodb()
                
                # Print combined sync message
                print(f"[INFO] Synced to/from DynamoDB tables: {self.PROJECTS_TABLE}, {self.STATES_TABLE}")
                print(f"[INFO] Synced to/from S3 bucket: {self.S3_BUCKET}")
                
                # Update last sync time
                self.last_sync_time = time.time()
                results['duration'] = self.last_sync_time - start_time
                results['success'] = True
                
            except Exception as e:
                results['success'] = False
                results['error'] = str(e)
                print(f"Error during full sync: {e}")
            
            return results
    
    def should_sync(self, interval_seconds: int = 5) -> bool:
        """
        Check if enough time has passed since last sync.
        
        Args:
            interval_seconds: Minimum seconds between syncs (default: 5)
            
        Returns:
            True if sync should be performed
        """
        if not self.is_enabled():
            return False
        
        current_time = time.time()
        return (current_time - self.last_sync_time) >= interval_seconds
    
    def sync_if_needed(self, interval_seconds: int = 5, current_project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Perform sync if enough time has passed since last sync.
        
        Args:
            interval_seconds: Minimum seconds between syncs (default: 5)
            current_project: Optional current project name for project-scoped syncing
            
        Returns:
            Sync results if performed, None otherwise
        """
        if self.should_sync(interval_seconds):
            return self.perform_full_sync(current_project=current_project)
        return None