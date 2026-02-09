"""
AI-powered finding analysis using AWS Bedrock or Google Gemini
"""
import json
import boto3
from typing import List, Dict, Optional, Tuple
from ..models.finding import Finding
from ..models.host import Host


class AIAnalyzer:
    """
    Uses AI (AWS Bedrock or Google Gemini) to analyze service evidence and generate security findings.
    """
    
    def __init__(self, config):
        """
        Initialize AI analyzer with configuration.
        
        Args:
            config: Configuration dictionary containing AI settings
        """
        self.config = config
        self.ai_type = config.get('ai_type', 'aws')
        
        # Load custom prompts for finding sections
        from ..utils.config_loader import ConfigLoader
        self.prompts = ConfigLoader.load_ai_prompts()
        
        # AWS Bedrock configuration
        self.profile = config.get('ai_aws_profile')
        self.account = config.get('ai_aws_account')
        self.region = config.get('ai_aws_region', 'us-east-1')
        self.model_id = config.get('ai_aws_model', 'us.anthropic.claude-sonnet-4-5-20250929-v1:0')
        
        # Anthropic configuration
        self.anthropic_token = config.get('ai_anthropic_token')
        self.anthropic_model = config.get('ai_anthropic_model', 'claude-sonnet-4-5-20250929')
        
        # OpenAI configuration
        self.openai_token = config.get('ai_openai_token')
        self.openai_model = config.get('ai_openai_model', 'gpt-4o')
        
        # Ollama configuration
        self.ollama_model = config.get('ai_ollama_model', 'llama3.1')
        self.ollama_host = config.get('ai_ollama_host', 'http://localhost:11434')
        
        # Azure OpenAI configuration
        self.azure_token = config.get('ai_azure_token')
        self.azure_endpoint = config.get('ai_azure_endpoint')
        self.azure_deployment = config.get('ai_azure_model')  # This is the deployment name
        self.azure_api_version = config.get('ai_azure_api_version', '2024-02-01')
        
        # Gemini configuration
        self.gemini_token = config.get('ai_gemini_token')
        self.gemini_model = config.get('ai_gemini_model', 'gemini-2.5-flash')
        
        # Common configuration
        self.max_tokens = config.get('ai_tokens', 64000)
        self.temperature = config.get('ai_temperature', 0.7)
        
        # Initialize client based on AI type
        self.client = None
        self.anthropic_client = None
        self.openai_client = None
        self.ollama_available = False
        self.azure_client = None
        self.gemini_client = None
        
        if self.ai_type == 'aws' and self.profile:
            try:
                # Use safe session creation to prevent ownership changes on credentials file
                from .aws_sync import create_boto3_session_safely
                
                session = create_boto3_session_safely(self.profile, self.region)
                self.client = session.client('bedrock-runtime', region_name=self.region)
                        
            except Exception as e:
                print(f"Error initializing Bedrock client: {e}")
        
        elif self.ai_type == 'anthropic' and self.anthropic_token:
            try:
                import anthropic
                self.anthropic_client = anthropic.Anthropic(api_key=self.anthropic_token)
            except Exception as e:
                print(f"Error initializing Anthropic client: {e}")
                import traceback
                traceback.print_exc()
        
        elif self.ai_type == 'openai' and self.openai_token:
            try:
                from openai import OpenAI
                self.openai_client = OpenAI(api_key=self.openai_token)
            except Exception as e:
                print(f"Error initializing OpenAI client: {e}")
                import traceback
                traceback.print_exc()
        
        elif self.ai_type == 'ollama':
            try:
                import ollama
                self.ollama_available = True
            except Exception as e:
                print(f"Error importing Ollama: {e}")
                import traceback
                traceback.print_exc()
        
        elif self.ai_type == 'azure' and self.azure_token and self.azure_endpoint:
            try:
                from openai import AzureOpenAI
                self.azure_client = AzureOpenAI(
                    api_key=self.azure_token,
                    api_version=self.azure_api_version,
                    azure_endpoint=self.azure_endpoint
                )
            except Exception as e:
                print(f"Error initializing Azure OpenAI client: {e}")
                import traceback
                traceback.print_exc()
        
        elif self.ai_type == 'gemini' and self.gemini_token:
            try:
                from google import genai
                self.gemini_client = genai.Client(api_key=self.gemini_token)
            except Exception as e:
                print(f"Error initializing Gemini client: {e}")
                import traceback
                traceback.print_exc()
    
    def is_configured(self) -> bool:
        """
        Check if AI analyzer is properly configured.
        
        Returns:
            True if AI is configured and ready
        """
        if self.ai_type == 'aws':
            return self.client is not None
        elif self.ai_type == 'anthropic':
            return self.anthropic_client is not None
        elif self.ai_type == 'openai':
            return self.openai_client is not None
        elif self.ai_type == 'ollama':
            return self.ollama_available
        elif self.ai_type == 'azure':
            return self.azure_client is not None
        elif self.ai_type == 'gemini':
            return self.gemini_client is not None
        return False
    
    def analyze_hosts(self, hosts: List[Host], batch_size: int = 5, include_evidence: bool = True,
                     progress_callback=None, enhance_mode: bool = False) -> List[Finding]:
        """
        Analyze hosts and their services to generate security findings.
        
        Args:
            hosts: List of Host objects to analyze
            batch_size: Number of hosts to analyze in each batch
            include_evidence: Whether to read and include proof file contents
            progress_callback: Optional callback function for progress updates
            enhance_mode: If True, use detailed enhancement prompts for findings (slower)
            
        Returns:
            List of Finding objects generated by AI
        """
        if not self.is_configured():
            return []
        
        all_findings = []
        total_batches = (len(hosts) + batch_size - 1) // batch_size
        
        # Process hosts in batches
        for batch_num, i in enumerate(range(0, len(hosts), batch_size), 1):
            batch = hosts[i:i+batch_size]
            
            if progress_callback:
                # Report batch progress
                batch_info = {
                    'batch_num': batch_num,
                    'total_batches': total_batches,
                    'hosts_in_batch': len(batch),
                    'host_ips': [h.ip for h in batch],
                    'total_services': sum(len(h.services) for h in batch)
                }
                progress_callback('batch_start', batch_info)
            
            batch_findings = self._analyze_batch(batch, include_evidence, progress_callback, enhance_mode)
            all_findings.extend(batch_findings)
            
            if progress_callback:
                # Report batch completion
                progress_callback('batch_complete', {
                    'batch_num': batch_num,
                    'findings_count': len(batch_findings)
                })
        
        return all_findings
    
    def _analyze_batch(self, hosts: List[Host], include_evidence: bool = True,
                      progress_callback=None, enhance_mode: bool = False) -> List[Finding]:
        """
        Analyze a batch of hosts using AI.
        
        Args:
            hosts: List of Host objects in this batch
            include_evidence: Whether to read and include proof file contents
            progress_callback: Optional callback for progress updates
            enhance_mode: If True, use detailed enhancement prompts
            
        Returns:
            List of Finding objects
        """
        # Prepare context from hosts
        context = self._prepare_context(hosts, include_evidence, progress_callback)
        
        # Generate prompt and extract screenshots
        prompt, screenshot_paths = self._build_analysis_prompt(context)
        
        # Call AI API (Bedrock or Gemini) with screenshots if available
        try:
            response = self._invoke_ai(prompt, screenshot_paths=screenshot_paths)
            
            # Parse findings from response
            findings = self._parse_findings(response, hosts, enhance_mode)
            
            return findings
            
        except Exception as e:
            print(f"Error during AI analysis: {e}")
            return []
    
    def _prepare_context(self, hosts: List[Host], include_evidence: bool = True,
                        progress_callback=None) -> Dict:
        """
        Prepare host and service data for AI analysis.
        
        Args:
            hosts: List of Host objects
            include_evidence: Whether to read and include proof file contents
            progress_callback: Optional callback for file reading progress
            
        Returns:
            Dictionary containing structured host/service data
        """
        context = {
            "hosts": []
        }
        
        for host in hosts:
            host_data = {
                "ip": host.ip,
                "hostname": host.hostname,
                "os": host.os,
                "services": []
            }
            
            for service in host.services:
                service_data = {
                    "port": service.port,
                    "protocol": service.protocol,
                    "service_name": service.service_name,
                    "service_version": service.service_version,
                    "extrainfo": service.extrainfo,
                    "evidence_count": len(service.proofs)
                }
                
                # Include proof types and optionally content
                if service.proofs:
                    service_data["evidence_types"] = [p.get("type") for p in service.proofs]
                    
                    # Read proof file contents if requested
                    if include_evidence:
                        evidence_contents = []
                        screenshot_files = []
                        
                        for proof in service.proofs[:3]:  # Limit to first 3 proofs per service
                            result_file = proof.get("result_file")
                            screenshot_file = proof.get("screenshot_file")
                            
                            # Read text result file
                            if result_file:
                                # Notify about file reading
                                if progress_callback:
                                    progress_callback('reading_file', {
                                        'host_ip': host.ip,
                                        'port': service.port,
                                        'file': result_file,
                                        'type': proof.get("type")
                                    })
                                
                                content = self._read_proof_file(result_file, max_chars=2000)
                                if content:
                                    evidence_contents.append({
                                        "type": proof.get("type"),
                                        "content": content
                                    })
                            
                            # Collect screenshot file path
                            if screenshot_file:
                                import os
                                if os.path.exists(screenshot_file):
                                    # Notify about screenshot reading
                                    if progress_callback:
                                        progress_callback('reading_file', {
                                            'host_ip': host.ip,
                                            'port': service.port,
                                            'file': screenshot_file,
                                            'type': f"{proof.get('type')}_screenshot"
                                        })
                                    
                                    screenshot_files.append({
                                        "type": proof.get("type"),
                                        "path": screenshot_file
                                    })
                        
                        if evidence_contents:
                            service_data["evidence_samples"] = evidence_contents
                        
                        if screenshot_files:
                            service_data["screenshots"] = screenshot_files
                
                host_data["services"].append(service_data)
            
            context["hosts"].append(host_data)
        
        return context
    
    def _read_proof_file(self, file_path: str, max_chars: int = 2000) -> Optional[str]:
        """
        Read a proof file and return its content (truncated if needed).
        
        Args:
            file_path: Path to the proof file
            max_chars: Maximum characters to read
            
        Returns:
            File content or None if read fails
        """
        try:
            import os
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(max_chars)
                if len(content) == max_chars:
                    content += "... [truncated]"
                return content
        except Exception:
            return None
    
    def _build_analysis_prompt(self, context: Dict) -> Tuple[str, List]:
        """
        Build the initial analysis prompt for AI (simple, no custom instructions).
        Also extracts screenshot paths for vision-capable models.
        
        Args:
            context: Host/service context data
            
        Returns:
            Tuple of (prompt string, list of screenshot paths)
        """
        # Extract all screenshot paths from context for vision models
        screenshot_paths = []
        for host_data in context.get("hosts", []):
            for service_data in host_data.get("services", []):
                for screenshot in service_data.get("screenshots", []):
                    screenshot_paths.append(screenshot.get("path"))
        
        prompt = f"""You are a penetration testing expert analyzing network scan results.
Analyze the following hosts and services to identify security findings.

For each finding, provide:
1. Name: A clear, specific title
2. Severity: Critical, High, Medium, Low, or Info
3. Description: Brief explanation of the vulnerability (2-3 sentences)
4. Impact: Brief security impact statement (1-2 sentences)
5. Remediation: Brief fix recommendations (2-3 bullet points)
6. CVSS Score: If applicable (0.0-10.0)
7. Host IP: The affected host
8. Port: The affected port (if applicable)

Scan Results:
{json.dumps(context, indent=2)}

Focus on:
- Outdated service versions with known vulnerabilities
- Insecure configurations
- Exposed sensitive services
- Missing security controls
- Potential attack vectors

Provide findings in JSON format as an array:
[
  {{
    "name": "Finding name",
    "severity": "High",
    "description": "Brief description",
    "impact": "Brief impact",
    "remediation": "Brief remediation",
    "cvss": 7.5,
    "host_ip": "192.168.1.10",
    "port": 22
  }}
]

Only include genuine security concerns. Return an empty array [] if no significant findings."""
        
        return prompt, screenshot_paths
    
    def _invoke_ai(self, prompt: str, screenshot_paths: List[str] = None) -> str:
        """
        Invoke AI API (AWS Bedrock, Anthropic, OpenAI, Ollama, Azure, or Gemini) with the prompt.
        Includes screenshots for vision-capable models.
        
        Args:
            prompt: The analysis prompt
            screenshot_paths: Optional list of screenshot file paths for vision analysis
            
        Returns:
            AI response text
        """
        if self.ai_type == 'aws':
            return self._invoke_bedrock(prompt, screenshot_paths)
        elif self.ai_type == 'anthropic':
            return self._invoke_anthropic(prompt, screenshot_paths)
        elif self.ai_type == 'openai':
            return self._invoke_openai(prompt, screenshot_paths)
        elif self.ai_type == 'ollama':
            return self._invoke_ollama(prompt, screenshot_paths)
        elif self.ai_type == 'azure':
            return self._invoke_azure(prompt, screenshot_paths)
        elif self.ai_type == 'gemini':
            return self._invoke_gemini(prompt, screenshot_paths)
        return ""
    
    def _invoke_bedrock(self, prompt: str, screenshot_paths: List[str] = None) -> str:
        """
        Invoke AWS Bedrock API with the prompt and optional screenshots.
        
        Args:
            prompt: The analysis prompt
            screenshot_paths: Optional list of screenshot file paths
            
        Returns:
            AI response text
        """
        import base64
        
        # Build message content with images if provided
        content = []
        
        # Add screenshots as image blocks (if any)
        if screenshot_paths:
            for img_path in screenshot_paths[:5]:  # Limit to 5 images
                try:
                    with open(img_path, 'rb') as f:
                        img_data = base64.b64encode(f.read()).decode('utf-8')
                        content.append({
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": img_data
                            }
                        })
                except Exception:
                    pass  # Skip failed images
        
        # Add text prompt
        content.append({
            "type": "text",
            "text": prompt
        })
        
        # Build request body for Claude model
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [
                {
                    "role": "user",
                    "content": content
                }
            ]
        }
        
        # Invoke model
        response = self.client.invoke_model(
            modelId=self.model_id,
            body=json.dumps(request_body)
        )
        
        # Parse response
        response_body = json.loads(response['body'].read())
        
        # Extract text from response
        if 'content' in response_body and len(response_body['content']) > 0:
            return response_body['content'][0]['text']
        
        return ""
    
    def _invoke_anthropic(self, prompt: str, screenshot_paths: List[str] = None) -> str:
        """
        Invoke Anthropic API with the prompt and optional screenshots.
        
        Args:
            prompt: The analysis prompt
            screenshot_paths: Optional list of screenshot file paths
            
        Returns:
            AI response text
        """
        try:
            import base64
            
            # Build message content with images if provided
            content = []
            
            # Add screenshots as image blocks (if any)
            if screenshot_paths:
                for img_path in screenshot_paths[:5]:  # Limit to 5 images
                    try:
                        with open(img_path, 'rb') as f:
                            img_data = base64.b64encode(f.read()).decode('utf-8')
                            content.append({
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": img_data
                                }
                            })
                    except Exception:
                        pass  # Skip failed images
            
            # Add text prompt
            content.append({
                "type": "text",
                "text": prompt
            })
            
            # Create message using Anthropic API
            message = self.anthropic_client.messages.create(
                model=self.anthropic_model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[
                    {"role": "user", "content": content}
                ]
            )
            
            # Extract text from response
            if message.content and len(message.content) > 0:
                return message.content[0].text
            
            return ""
            
        except Exception as e:
            print(f"Error invoking Anthropic: {e}")
            import traceback
            traceback.print_exc()
            return ""
    
    def _invoke_openai(self, prompt: str, screenshot_paths: List[str] = None) -> str:
        """
        Invoke OpenAI API with the prompt and optional screenshots.
        
        Args:
            prompt: The analysis prompt
            screenshot_paths: Optional list of screenshot file paths
            
        Returns:
            AI response text
        """
        try:
            import base64
            
            # Build message content
            content = []
            
            # Add screenshots for vision models (gpt-4-vision, gpt-4o)
            if screenshot_paths and ('vision' in self.openai_model.lower() or 'gpt-4o' in self.openai_model.lower()):
                for img_path in screenshot_paths[:5]:
                    try:
                        with open(img_path, 'rb') as f:
                            img_data = base64.b64encode(f.read()).decode('utf-8')
                            content.append({
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{img_data}"
                                }
                            })
                    except Exception:
                        pass  # Skip failed images
            
            # Add text prompt
            content.append({
                "type": "text",
                "text": prompt
            })
            
            # Create chat completion using OpenAI API
            response = self.openai_client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": "You are a penetration testing expert analyzing security vulnerabilities."},
                    {"role": "user", "content": content}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            # Extract text from response
            if response.choices and len(response.choices) > 0:
                return response.choices[0].message.content
            
            return ""
            
        except Exception as e:
            print(f"Error invoking OpenAI: {e}")
            import traceback
            traceback.print_exc()
            return ""
    
    def _invoke_ollama(self, prompt: str, screenshot_paths: List[str] = None) -> str:
        """
        Invoke Ollama API with the prompt and optional screenshots.
        
        Args:
            prompt: The analysis prompt
            screenshot_paths: Optional list of screenshot file paths
            
        Returns:
            AI response text
        """
        try:
            import ollama
            
            # Build message content
            # Note: Ollama vision support varies by model (llava, bakllava, etc.)
            images = []
            if screenshot_paths and 'llava' in self.ollama_model.lower():
                for img_path in screenshot_paths[:5]:
                    try:
                        images.append(img_path)
                    except Exception:
                        pass
            
            # Create chat completion using Ollama
            response = ollama.chat(
                model=self.ollama_model,
                messages=[
                    {"role": "system", "content": "You are a penetration testing expert analyzing security vulnerabilities."},
                    {"role": "user", "content": prompt, "images": images if images else None}
                ],
                options={
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens
                }
            )
            
            # Extract text from response
            if response and 'message' in response:
                return response['message']['content']
            
            return ""
            
        except Exception as e:
            print(f"Error invoking Ollama: {e}")
            import traceback
            traceback.print_exc()
            return ""
    
    def _invoke_azure(self, prompt: str, screenshot_paths: List[str] = None) -> str:
        """
        Invoke Azure OpenAI API with the prompt and optional screenshots.
        
        Args:
            prompt: The analysis prompt
            screenshot_paths: Optional list of screenshot file paths
            
        Returns:
            AI response text
        """
        try:
            import base64
            
            # Build message content (vision support if gpt-4-vision deployment)
            content = []
            
            # Add screenshots if deployment supports vision
            if screenshot_paths:
                for img_path in screenshot_paths[:5]:
                    try:
                        with open(img_path, 'rb') as f:
                            img_data = base64.b64encode(f.read()).decode('utf-8')
                            content.append({
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{img_data}"
                                }
                            })
                    except Exception:
                        pass
            
            # Add text prompt
            content.append({
                "type": "text",
                "text": prompt
            })
            
            # Create chat completion using Azure OpenAI API
            response = self.azure_client.chat.completions.create(
                model=self.azure_deployment,  # This is the deployment name
                messages=[
                    {"role": "system", "content": "You are a penetration testing expert analyzing security vulnerabilities."},
                    {"role": "user", "content": content}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            # Extract text from response
            if response.choices and len(response.choices) > 0:
                return response.choices[0].message.content
            
            return ""
            
        except Exception as e:
            print(f"Error invoking Azure OpenAI: {e}")
            import traceback
            traceback.print_exc()
            return ""
    
    def _invoke_gemini(self, prompt: str, screenshot_paths: List[str] = None) -> str:
        """
        Invoke Google Gemini API with the prompt and optional screenshots.
        
        Args:
            prompt: The analysis prompt
            screenshot_paths: Optional list of screenshot file paths
            
        Returns:
            AI response text
        """
        try:
            from google.genai import types
            
            # Build contents with images
            contents = []
            
            # Add screenshots
            if screenshot_paths:
                for img_path in screenshot_paths[:5]:
                    try:
                        with open(img_path, 'rb') as f:
                            img_data = f.read()
                            contents.append(types.Part.from_bytes(
                                data=img_data,
                                mime_type="image/png"
                            ))
                    except Exception:
                        pass
            
            # Add text prompt
            contents.append(prompt)
            
            # Generate content using the client
            response = self.gemini_client.models.generate_content(
                model=self.gemini_model,
                contents=contents
            )
            
            # Return the response text
            if response and hasattr(response, 'text'):
                return response.text
            elif response and hasattr(response, 'candidates'):
                # Try to extract from candidates
                if response.candidates and len(response.candidates) > 0:
                    candidate = response.candidates[0]
                    if hasattr(candidate, 'content'):
                        content = candidate.content
                        if hasattr(content, 'parts') and content.parts:
                            return content.parts[0].text
            
            return ""
            
        except Exception as e:
            print(f"Error invoking Gemini: {e}")
            import traceback
            traceback.print_exc()
            return ""
    
    def _refine_finding_field(self, field_name: str, field_content: str, finding_context: str) -> str:
        """
        Refine a finding field using custom prompt.
        
        Args:
            field_name: Field to refine ('name', 'description', 'impact', or 'remediation')
            field_content: Current content of the field
            finding_context: Context about the finding (name, severity, etc.)
            
        Returns:
            Refined field content
        """
        # Get the appropriate custom prompt
        prompt_key = f'{field_name}_prompt'
        custom_prompt = self.prompts.get(prompt_key, '')
        
        if not custom_prompt:
            # No custom prompt, return original
            return field_content
        
        # Build refinement prompt - special handling for name field
        if field_name == 'name':
            refinement_prompt = f"""{custom_prompt}

Finding Context:
{finding_context}

Current Title:
{field_content}

Provide ONLY the refined title (no explanations, no formatting, no quotes):"""
        else:
            refinement_prompt = f"""{custom_prompt}

Finding Context:
{finding_context}

Current {field_name.capitalize()}:
{field_content}

Provide ONLY the refined {field_name} content below (no additional formatting, no field labels):"""
        
        try:
            # Invoke AI to refine the field
            refined_content = self._invoke_ai(refinement_prompt)
            
            # Clean up response - remove any markdown formatting or labels
            refined_content = refined_content.strip()
            
            # Remove quotes if present (common for title refinement)
            if refined_content.startswith('"') and refined_content.endswith('"'):
                refined_content = refined_content[1:-1].strip()
            if refined_content.startswith("'") and refined_content.endswith("'"):
                refined_content = refined_content[1:-1].strip()
            
            # Remove common prefixes that AI might add
            prefixes_to_remove = [
                f"**{field_name.capitalize()}:**",
                f"{field_name.capitalize()}:",
                "**Description:**",
                "**Impact:**",
                "**Remediation:**",
                "**Title:**",
                "**Name:**",
                "Description:",
                "Impact:",
                "Remediation:",
                "Title:",
                "Name:"
            ]
            
            for prefix in prefixes_to_remove:
                if refined_content.startswith(prefix):
                    refined_content = refined_content[len(prefix):].strip()
            
            return refined_content if refined_content else field_content
            
        except Exception as e:
            print(f"Error refining {field_name}: {e}")
            return field_content
    
    def _classify_cwe(self, finding_data: Dict) -> Optional[str]:
        """
        Classify a finding's CWE using AI.
        
        Args:
            finding_data: Dictionary containing finding information
            
        Returns:
            CWE string or None if classification fails
        """
        # Get CWE prompt
        cwe_prompt_template = self.prompts.get('cwe_prompt', '')
        if not cwe_prompt_template:
            return None
        
        # Build CWE classification prompt
        finding_summary = f"""Finding Name: {finding_data.get('name', 'Unknown')}
Severity: {finding_data.get('severity', 'Unknown')}
Description: {finding_data.get('description', 'No description')}
Impact: {finding_data.get('impact', 'No impact specified')}"""
        
        cwe_prompt = f"{cwe_prompt_template}\n\nFinding to classify:\n{finding_summary}"
        
        try:
            # Invoke AI with CWE prompt
            response = self._invoke_ai(cwe_prompt)
            
            # Clean up response - extract CWE string
            cwe = response.strip()
            
            # Validate it looks like a CWE
            if cwe.startswith('CWE-'):
                return cwe
            
            return None
            
        except Exception as e:
            print(f"Error classifying CWE: {e}")
            return None
    
    def _parse_findings(self, response: str, hosts: List[Host], enhance_mode: bool = False) -> List[Finding]:
        """
        Parse AI response into Finding objects.
        
        Args:
            response: AI response text
            hosts: Original host objects for reference
            enhance_mode: If True, use detailed enhancement prompts for each field
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            # Extract JSON from response
            # Look for JSON array in the response
            json_start = response.find('[')
            json_end = response.rfind(']') + 1
            
            if json_start == -1 or json_end == 0:
                # No JSON found
                return findings
            
            json_str = response[json_start:json_end]
            findings_data = json.loads(json_str)
            
            # Create Finding objects
            for finding_dict in findings_data:
                # Find the host by IP
                host_ip = finding_dict.get('host_ip')
                port = finding_dict.get('port')
                host_id = None
                proof_files = []
                
                for host in hosts:
                    if host.ip == host_ip:
                        host_id = host.host_id
                        
                        # Collect proof files for this port (including screenshots)
                        if port:
                            for service in host.services:
                                if service.port == port:
                                    for proof in service.proofs:
                                        result_file = proof.get('result_file')
                                        screenshot_file = proof.get('screenshot_file')
                                        
                                        if result_file:
                                            proof_files.append(result_file)
                                        if screenshot_file:
                                            proof_files.append(screenshot_file)
                        break
                
                # Get initial field values
                initial_name = finding_dict.get('name', 'Unknown Finding')
                initial_description = finding_dict.get('description', '')
                initial_impact = finding_dict.get('impact', '')
                initial_remediation = finding_dict.get('remediation', '')
                
                # Build finding context for refinement
                finding_context = f"""Finding Name: {initial_name}
Severity: {finding_dict.get('severity', 'Unknown')}
CVSS: {finding_dict.get('cvss', 'N/A')}
Host: {finding_dict.get('host_ip', 'Unknown')}
Port: {finding_dict.get('port', 'N/A')}
Description: {initial_description[:200]}..."""
                
                # Apply enhancement if requested
                if enhance_mode:
                    # Refine each field with custom prompts (including name)
                    refined_name = self._refine_finding_field('name', initial_name, finding_context)
                    refined_description = self._refine_finding_field('description', initial_description, finding_context)
                    refined_impact = self._refine_finding_field('impact', initial_impact, finding_context)
                    refined_remediation = self._refine_finding_field('remediation', initial_remediation, finding_context)
                    
                    # Classify CWE for this finding (using refined description and impact)
                    cwe_finding_data = {
                        'name': finding_dict.get('name', 'Unknown'),
                        'severity': finding_dict.get('severity', 'Unknown'),
                        'description': refined_description,
                        'impact': refined_impact
                    }
                    cwe = self._classify_cwe(cwe_finding_data)
                else:
                    # Use basic fields without enhancement
                    refined_name = initial_name
                    refined_description = initial_description
                    refined_impact = initial_impact
                    refined_remediation = initial_remediation
                    cwe = None
                
                # Create finding with appropriate fields
                finding = Finding(
                    host_id=host_id,
                    name=refined_name,
                    severity=finding_dict.get('severity', 'Info'),
                    description=refined_description,
                    port=port,
                    cvss=finding_dict.get('cvss'),
                    cwe=cwe,
                    remediation=refined_remediation,
                    impact=refined_impact,
                    proof_file=', '.join(proof_files) if proof_files else None
                )
                
                findings.append(finding)
        
        except json.JSONDecodeError as e:
            print(f"Error parsing AI response JSON: {e}")
        except Exception as e:
            print(f"Error creating findings from AI response: {e}")
        
        return findings
    
    def analyze_single_service(self, host: Host, service, evidence_content: Optional[str] = None) -> List[Finding]:
        """
        Analyze a single service with optional evidence content.
        
        Args:
            host: Host object
            service: Service object
            evidence_content: Optional evidence file content
            
        Returns:
            List of Finding objects
        """
        if not self.is_configured():
            return []
        
        # Build focused prompt for single service
        context = {
            "host": {
                "ip": host.ip,
                "hostname": host.hostname,
                "os": host.os
            },
            "service": {
                "port": service.port,
                "protocol": service.protocol,
                "service_name": service.service_name,
                "service_version": service.service_version,
                "extrainfo": service.extrainfo
            }
        }
        
        if evidence_content:
            context["evidence"] = evidence_content[:5000]  # Limit evidence size
        
        prompt = f"""Analyze this specific service for security issues:

{json.dumps(context, indent=2)}

Provide findings in JSON format as an array. Only include if there are genuine security concerns."""
        
        try:
            response = self._invoke_ai(prompt)
            findings = self._parse_findings(response, [host])
            return findings
        except Exception as e:
            print(f"Error analyzing service: {e}")
            return []