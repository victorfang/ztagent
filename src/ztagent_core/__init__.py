# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

"""ZTAgent Core: Zero Trust Security for AI Agents, by Victor Fang."""

from .api import create_app
from .gateway import SecureAgentGateway
from .models import AgentRequest, AgentResponse, Message, Principal
from .tools import ToolRegistry, ToolSpec

__all__ = [
    "AgentRequest",
    "AgentResponse",
    "Message",
    "Principal",
    "SecureAgentGateway",
    "ToolRegistry",
    "ToolSpec",
    "create_app",
]

__version__ = "0.1.1"
