import streamlit as st
import json
from datetime import datetime
from utils.constants import (
    get_ai_provider,
    get_openai_config,
    get_bedrock_config,
    AWS_DEFAULT_PROFILE,
    AWS_DEFAULT_REGION
)


def render_chatbot_dialog(dm):
    """Render chatbot dialog."""
    # Initialize session state only if not exists
    if 'chat_messages' not in st.session_state:
        st.session_state.chat_messages = []
    
    # Get AI provider configuration
    provider = get_ai_provider()
    
    if provider == 'aws':
        # Get bedrock configuration dynamically
        bedrock_config = get_bedrock_config()
        MODEL_ID = bedrock_config.get('model_id', 'us.anthropic.claude-sonnet-4-5-20250929-v1:0')
        REGION = AWS_DEFAULT_REGION
        # Get model display name
        available_models = bedrock_config.get('available_models', [])
        model_name = next((m['name'] for m in available_models if m['id'] == MODEL_ID), MODEL_ID)
    else:
        # OpenAI configuration
        openai_config = get_openai_config()
        MODEL_ID = openai_config.get('model', 'gpt-3.5-turbo')
        REGION = None
        # Get model display name
        available_models = openai_config.get('available_models', [])
        model_name = next((m['name'] for m in available_models if m['id'] == MODEL_ID), MODEL_ID)
    
    # Get current project data
    project = st.session_state.get('current_project')
    render_chatbot_dialog_content(provider, MODEL_ID, model_name, REGION, project, dm)


@st.dialog("AI Assistant", width="large")
def render_chatbot_dialog_content(provider, model_id, model_name, region, project, dm):
    """Render the chatbot dialog content"""
    
    # Display caption based on provider with model name
    if provider == 'aws':
        caption = f"Powered by AWS Bedrock | Model: {model_name}"
    else:
        caption = f"Powered by OpenAI | Model: {model_name}"
    
    if project:
        st.caption(f"{caption} | Project: {project.name}")
    else:
        st.caption(caption)
    
    # Create tabs for different functionalities. Allows for adding more tabs to different websites (iframes)
    tabs = st.tabs(["💬 Chat"])
    
    # Chat Tab - Current functionality
    with tabs[0]:
        # Display chat messages
        for message in st.session_state.chat_messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])
        
        # Chat input
        user_input = st.chat_input("Ask a question...", key="chatbot_input")
        
        if user_input:
            # Add user message to chat
            st.session_state.chat_messages.append({
                "role": "user",
                "content": user_input,
                "timestamp": datetime.now().isoformat()
            })
            
            # Get response based on provider
            with st.spinner("Thinking..."):
                if provider == 'aws':
                    response = invoke_bedrock_model(
                        user_input,
                        model_id,
                        region,
                        st.session_state.chat_messages,
                        project
                    )
                else:
                    response = invoke_openai_model(
                        user_input,
                        model_id,
                        st.session_state.chat_messages,
                        project
                    )
            
            # Add assistant response to chat history
            st.session_state.chat_messages.append({
                "role": "assistant",
                "content": response,
                "timestamp": datetime.now().isoformat()
            })
            
            # Keep dialog open by setting button clicked flag
            st.session_state._dialog_button_clicked = True
            st.rerun()
    
    # Can add additional tabs. e.g Iframe
    #with chatgpt_tab:
    #    iframe_html = """
    #    <iframe
    #        src="URL"
    #        width="100%"
    #        height="600"
    #        style="border: 1px solid #ddd; border-radius: 4px;"
    #        sandbox="allow-same-origin allow-scripts allow-popups allow-forms"
    #    ></iframe>
    #    """
    #    st.components.v1.html(iframe_html, height=620, scrolling=True)
    
    # Close and Clear buttons
    st.markdown("---")
    col1, col2, col3 = st.columns([4, 1, 1])
    with col2:
        if st.button("Clear Chat", key="clear_chat", width='stretch'):
            st.session_state.chat_messages = []
            st.session_state._dialog_button_clicked = True
            st.rerun()
    with col3:
        if st.button("Close", key="close_chatbot", type="primary", width='stretch'):
            dm.close_dialog('chatbot')
            st.rerun()


def build_project_context(project):
    """
    Build comprehensive project context for AI models.
    
    This function is a wrapper that delegates to the project's to_ai_context() method.
    Kept for backward compatibility with existing code.
    
    Args:
        project: Current project data
        
    Returns:
        Dictionary containing project context
    """
    if not project:
        return None
    
    # Delegate to model's to_ai_context() method
    if hasattr(project, 'to_ai_context'):
        return project.to_ai_context()
    
    # Fallback for backward compatibility (should not be needed)
    return {
        "project_name": project.name,
        "project_description": project.description,
        "networks": [],
        "credentials": [],
        "todos": project.todo if hasattr(project, 'todo') else []
    }


def invoke_openai_model(query: str, model: str, chat_history: list, project=None):
    """
    Invoke OpenAI model for conversational AI.
    
    Args:
        query: User's question
        model: OpenAI model name
        chat_history: Previous chat messages for context
        project: Current project data for context
        
    Returns:
        Response text from the model
    """
    try:
        from openai import OpenAI
    except ImportError:
        return "❌ openai package not installed. Please run: pip install openai"
    
    try:
        # Get OpenAI configuration
        openai_config = get_openai_config()
        api_token = openai_config.get('api_token', '')
        base_url = openai_config.get('base_url', 'https://api.openai.com/v1')
        max_tokens = openai_config.get('max_tokens', 4096)
        temperature = openai_config.get('temperature', 0.7)
        
        # Check if this is a local server (doesn't require API token)
        is_local_server = base_url and ('localhost' in base_url or '127.0.0.1' in base_url)
        
        if not api_token and not is_local_server:
            return "❌ API token not configured. Please set it in AI Settings."
        
        # Create OpenAI client with configurable base_url
        # For local servers, use a placeholder token if none provided
        client = OpenAI(
            api_key=api_token if api_token else "not-needed",
            base_url=base_url
        )
        
        # Build messages array
        messages = []
        
        # Add system message with project context if available
        if project:
            project_context = build_project_context(project)
            context_json = json.dumps(project_context, indent=2)
            
            system_message = f"""You are an AI assistant helping with a penetration testing project. You have access to the current project data below.

PROJECT DATA:
{context_json}

When answering questions:
- Reference specific IPs, hosts, services, and findings from the project data
- Provide security recommendations based on discovered services and findings
- Help with analysis, reporting, and next steps
- Be specific and actionable in your responses
- If asked about networks, hosts, or findings, use the exact data provided above

You are knowledgeable about penetration testing, security vulnerabilities, and remediation strategies."""
            
            messages.append({"role": "system", "content": system_message})
        
        # Add conversation history (last 10 messages for context)
        for msg in chat_history[-10:]:
            if msg["role"] in ["user", "assistant"]:
                messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })
        
        # Add current query
        messages.append({"role": "user", "content": query})
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature
        )
        
        # Extract response text
        response_text = response.choices[0].message.content
        
        return response_text
        
    except Exception as e:
        return f"❌ OpenAI Error: {str(e)}"


def invoke_bedrock_model(query: str, model_id: str, region: str, chat_history: list, project=None):
    """
    Invoke AWS Bedrock model directly for conversational AI.
    
    Args:
        query: User's question
        model_id: Bedrock model identifier
        region: AWS region
        chat_history: Previous chat messages for context
        project: Current project data for context
        
    Returns:
        Response text from the model
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
    except ImportError:
        return "❌ boto3 not installed. Please run: pip install boto3"
    
    try:
        # Create Bedrock Runtime client using profile
        try:
            session = boto3.Session(profile_name=AWS_DEFAULT_PROFILE)
            bedrock_runtime = session.client(
                'bedrock-runtime',
                region_name=region
            )
        except ProfileNotFound:
            # Fallback to default credentials if profile not found
            bedrock_runtime = boto3.client(
                'bedrock-runtime',
                region_name=region
            )
        
        # Build project context if available
        system_prompts = []
        if project:
            project_context = build_project_context(project)
            context_json = json.dumps(project_context, indent=2)
            system_prompt = f"""You are an AI assistant helping with a penetration testing project. You have access to the current project data below.

PROJECT DATA:
{context_json}

When answering questions:
- Reference specific IPs, hosts, services, and findings from the project data
- Provide security recommendations based on discovered services and findings
- Help with analysis, reporting, and next steps
- Be specific and actionable in your responses
- If asked about networks, hosts, or findings, use the exact data provided above

You are knowledgeable about penetration testing, security vulnerabilities, and remediation strategies."""

            system_prompts.append({"text": system_prompt})
        
        # Build conversation history for Claude models
        messages = []
        for msg in chat_history[-10:]:  # Keep last 10 messages for context
            if msg["role"] in ["user", "assistant"]:
                messages.append({
                    "role": msg["role"],
                    "content": [{"text": msg["content"]}]
                })
        
        # Add current query
        messages.append({
            "role": "user",
            "content": [{"text": query}]
        })
        
        # Get bedrock configuration for max_tokens and temperature
        from utils.constants import get_bedrock_config
        bedrock_config = get_bedrock_config()
        
        # Invoke the model using Converse API
        converse_params = {
            "modelId": model_id,
            "messages": messages,
            "inferenceConfig": {
                "maxTokens": bedrock_config.get('max_tokens', 4096),
                "temperature": bedrock_config.get('temperature', 0.7)
            }
        }
        
        # Add system prompts if we have project context
        if system_prompts:
            converse_params["system"] = system_prompts
        
        response = bedrock_runtime.converse(**converse_params)
        
        # Extract response text
        response_text = response['output']['message']['content'][0]['text']
        
        return response_text
        
    except (NoCredentialsError, ProfileNotFound) as e:
        return f"❌ AWS Credentials Error: {str(e)}\n\nPlease ensure {AWS_DEFAULT_PROFILE} is configured."
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        return f"❌ AWS Error ({error_code}): {error_msg}"
        
    except Exception as e:
        return f"❌ Unexpected Error: {str(e)}"
