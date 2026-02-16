"""
Finding enhancement utilities.

This module provides optimized finding enhancement that reduces AI API calls
from 5 per finding to 1 per finding - an 80% cost reduction and 5× speed improvement.
"""

from typing import Dict
import json


class FindingEnhancer:
    """
    Enhances findings with detailed AI analysis using optimized batched calls.
    
    Instead of making 5 separate AI calls per finding (name, description, impact,
    remediation, CWE), this makes a single batched call that refines all fields
    at once, providing better context and significant cost/time savings.
    
    Attributes:
        provider: AI provider instance
        prompts: Dictionary of custom prompts for enhancement
    """
    
    def __init__(self, provider, prompts: Dict):
        """
        Initialize finding enhancer.
        
        Args:
            provider: BaseAIProvider instance for making AI calls
            prompts: Dictionary containing custom enhancement prompts
        """
        self.provider = provider
        self.prompts = prompts
    
    def enhance_finding(self, finding_dict: Dict) -> Dict:
        """
        Enhance all finding fields in a single AI call.
        
        Replaces 5 separate AI calls with 1 batched call that refines:
        - Name/Title
        - Description
        - Impact
        - Remediation
        - CWE classification
        
        Args:
            finding_dict: Dictionary containing initial finding data
            
        Returns:
            Enhanced finding dictionary with refined fields
        """
        # Build single comprehensive enhancement prompt
        prompt = self._build_enhancement_prompt(finding_dict)
        
        # Single AI call for all enhancements
        response = self.provider.generate_response(prompt)
        
        # Parse and apply enhancements
        enhanced = self._parse_enhancement_response(response, finding_dict)
        
        return enhanced
    
    def _build_enhancement_prompt(self, finding: Dict) -> str:
        """
        Build comprehensive prompt that refines all fields at once.
        
        This single prompt asks the AI to enhance all finding fields
        simultaneously, providing better context than separate calls.
        
        Args:
            finding: Initial finding dictionary
            
        Returns:
            Comprehensive enhancement prompt
        """
        # Get custom prompts for context (use defaults if not configured)
        name_guidance = self.prompts.get('name_prompt', 
            'Refine the title to be clear, specific, and professional.')
        desc_guidance = self.prompts.get('description_prompt',
            'Expand the description with technical details.')
        impact_guidance = self.prompts.get('impact_prompt',
            'Elaborate the impact with security implications.')
        remediation_guidance = self.prompts.get('remediation_prompt',
            'Provide comprehensive remediation steps.')
        cwe_guidance = self.prompts.get('cwe_prompt',
            'Classify the CWE category in format: CWE-XXXX')
        
        prompt = f"""Enhance this security finding by refining all fields comprehensively:

Current Finding:
- Name: {finding.get('name', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}
- CVSS: {finding.get('cvss', 'N/A')}
- Host: {finding.get('host_ip', 'Unknown')}
- Port: {finding.get('port', 'N/A')}
- Description: {finding.get('description', 'No description')}
- Impact: {finding.get('impact', 'Not specified')}
- Remediation: {finding.get('remediation', 'Not specified')}

Enhancement Instructions:
1. NAME: {name_guidance}
2. DESCRIPTION: {desc_guidance}
3. IMPACT: {impact_guidance}
4. REMEDIATION: {remediation_guidance}
5. CWE: {cwe_guidance}

Respond in JSON format with ALL enhanced fields:
{{
  "name": "Enhanced title here",
  "description": "Enhanced detailed description here (2-3 paragraphs)",
  "impact": "Enhanced detailed impact statement here (1-2 paragraphs)",
  "remediation": "Enhanced comprehensive remediation steps here (detailed bullet points or numbered list)",
  "cwe": "CWE-XXX"
}}

Provide ONLY the JSON object, no additional text."""
        
        return prompt
    
    def _parse_enhancement_response(self, response: str, original: Dict) -> Dict:
        """
        Parse JSON response with enhanced fields.
        
        Extracts the enhanced fields from AI response and merges them
        with the original finding data.
        
        Args:
            response: AI response text containing JSON
            original: Original finding dictionary
            
        Returns:
            Enhanced finding dictionary
        """
        try:
            # Find JSON in response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start == -1 or json_end == 0:
                print("Warning: No JSON found in enhancement response")
                return original
            
            # Extract and parse JSON
            json_str = response[json_start:json_end]
            enhanced_fields = json.loads(json_str)
            
            # Merge enhanced fields with original
            result = original.copy()
            
            # Apply enhancements with cleanup
            if 'name' in enhanced_fields:
                result['name'] = self._cleanup_field(enhanced_fields['name'])
            if 'description' in enhanced_fields:
                result['description'] = self._cleanup_field(enhanced_fields['description'])
            if 'impact' in enhanced_fields:
                result['impact'] = self._cleanup_field(enhanced_fields['impact'])
            if 'remediation' in enhanced_fields:
                result['remediation'] = self._cleanup_field(enhanced_fields['remediation'])
            if 'cwe' in enhanced_fields:
                cwe = enhanced_fields['cwe'].strip()
                # Validate CWE format
                if cwe and (cwe.startswith('CWE-') or cwe.upper().startswith('CWE-')):
                    result['cwe'] = cwe.upper() if not cwe.startswith('CWE-') else cwe
            
            return result
            
        except json.JSONDecodeError as e:
            print(f"Error parsing enhancement JSON: {e}")
            return original
        except Exception as e:
            print(f"Error processing enhancement: {e}")
            return original
    
    def _cleanup_field(self, text: str) -> str:
        """
        Clean up enhanced field text.
        
        Removes common AI response artifacts like field labels,
        quotes, and excessive whitespace.
        
        Args:
            text: Raw field text from AI
            
        Returns:
            Cleaned field text
        """
        if not text:
            return text
        
        # Use naming_utils for text cleanup
        from ...utils.naming_utils import (
            remove_ai_response_prefixes,
            normalize_whitespace
        )
        
        # Remove prefixes and normalize
        cleaned = remove_ai_response_prefixes(text)
        cleaned = normalize_whitespace(cleaned)
        
        return cleaned
    