"""
Findings Storage Utility

Manages storage and retrieval of findings in a separate JSON file to reduce
project JSON size for DynamoDB optimization.

Findings are stored in: scan_results/<project_name>/findings.json
Project JSON only stores finding references (id and name).
"""

import json
import os
from typing import List, Dict, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class FindingsStorage:
    """Manages separate storage of findings data."""
    
    def __init__(self, project_name: str, scan_results_base: str = "scan_results"):
        """
        Initialize findings storage for a project.
        
        Args:
            project_name: Name of the project
            scan_results_base: Base directory for scan results
        """
        self.project_name = project_name
        self.scan_results_base = scan_results_base
        self.findings_dir = os.path.join(scan_results_base, project_name)
        self.findings_file = os.path.join(self.findings_dir, "findings.json")
        
        # Ensure directory exists
        os.makedirs(self.findings_dir, exist_ok=True)
        
        # Initialize findings file if it doesn't exist
        if not os.path.exists(self.findings_file):
            self._save_findings_file([])
    
    def _save_findings_file(self, findings: List[Dict]) -> None:
        """Save findings to file."""
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(findings, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving findings file: {e}")
            raise
    
    def _load_findings_file(self) -> List[Dict]:
        """Load findings from file."""
        try:
            if os.path.exists(self.findings_file):
                with open(self.findings_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logger.error(f"Error loading findings file: {e}")
            return []
    
    def get_next_id(self) -> int:
        """Get the next available finding ID."""
        findings = self._load_findings_file()
        if not findings:
            return 1
        # Find max ID and increment
        max_id = max(f.get('id', 0) for f in findings)
        return max_id + 1
    
    def add_finding(self, finding_data: Dict) -> int:
        """
        Add a new finding and return its ID.
        
        Args:
            finding_data: Full finding data dictionary
            
        Returns:
            The assigned finding ID
        """
        findings = self._load_findings_file()
        
        # Assign ID if not present
        if 'id' not in finding_data:
            finding_data['id'] = self.get_next_id()
        
        # Check if finding with this ID already exists
        existing_index = next((i for i, f in enumerate(findings) if f.get('id') == finding_data['id']), None)
        
        if existing_index is not None:
            # Update existing finding
            findings[existing_index] = finding_data
        else:
            # Add new finding
            findings.append(finding_data)
        
        self._save_findings_file(findings)
        return finding_data['id']
    
    def get_finding(self, finding_id: int) -> Optional[Dict]:
        """
        Get a finding by ID.
        
        Args:
            finding_id: The finding ID
            
        Returns:
            Finding data dictionary or None if not found
        """
        findings = self._load_findings_file()
        return next((f for f in findings if f.get('id') == finding_id), None)
    
    def get_all_findings(self) -> List[Dict]:
        """Get all findings."""
        return self._load_findings_file()
    
    def get_findings_by_ids(self, finding_ids: List[int]) -> List[Dict]:
        """
        Get multiple findings by their IDs.
        
        Args:
            finding_ids: List of finding IDs
            
        Returns:
            List of finding data dictionaries
        """
        findings = self._load_findings_file()
        id_set = set(finding_ids)
        return [f for f in findings if f.get('id') in id_set]
    
    def update_finding(self, finding_id: int, finding_data: Dict) -> bool:
        """
        Update an existing finding.
        
        Args:
            finding_id: The finding ID to update
            finding_data: New finding data
            
        Returns:
            True if updated, False if not found
        """
        findings = self._load_findings_file()
        
        for i, f in enumerate(findings):
            if f.get('id') == finding_id:
                # Preserve the ID
                finding_data['id'] = finding_id
                findings[i] = finding_data
                self._save_findings_file(findings)
                return True
        
        return False
    
    def delete_finding(self, finding_id: int) -> bool:
        """
        Delete a finding by ID.
        
        Args:
            finding_id: The finding ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        findings = self._load_findings_file()
        original_len = len(findings)
        
        findings = [f for f in findings if f.get('id') != finding_id]
        
        if len(findings) < original_len:
            self._save_findings_file(findings)
            return True
        
        return False
    
    def migrate_from_inline_findings(self, inline_findings: List[Dict]) -> List[Dict]:
        """
        Migrate inline findings to storage and return finding references.
        
        Args:
            inline_findings: List of full finding dictionaries from project JSON
            
        Returns:
            List of finding references (id and name only)
        """
        references = []
        
        for finding in inline_findings:
            # Skip if already a reference (has id but minimal data)
            if 'id' in finding and len(finding) <= 3:
                references.append(finding)
                continue
            
            # Add to storage
            finding_id = self.add_finding(finding)
            
            # Create reference
            reference = {
                'id': finding_id,
                'n': finding.get('n', finding.get('name', 'Unknown'))
            }
            
            # Include severity for quick filtering/display
            if 'sev' in finding:
                reference['sev'] = finding['sev']
            elif 'severity' in finding:
                # Convert to code if needed
                from models.finding import SEVERITY_TO_CODE
                reference['sev'] = SEVERITY_TO_CODE.get(finding['severity'], finding['severity'])
            
            references.append(reference)
        
        return references
    
    def expand_finding_references(self, references: List[Dict]) -> List[Dict]:
        """
        Expand finding references to full finding data.
        
        Args:
            references: List of finding references (id and name)
            
        Returns:
            List of full finding dictionaries
        """
        if not references:
            return []
        
        # Extract IDs from references
        finding_ids = [ref.get('id') for ref in references if 'id' in ref]
        
        # Get full findings
        return self.get_findings_by_ids(finding_ids)