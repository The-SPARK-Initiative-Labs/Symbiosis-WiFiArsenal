#!/usr/bin/env python3
"""
MCP Client for The Operator
Connects to MCP servers and provides tools to Claude API
"""

import asyncio
import json
import subprocess
import sys
from typing import Dict, List, Any, Optional
from pathlib import Path

# MCP Server definitions - path to each server script
MCP_SERVERS = {
    'filesystem': '/home/ov3rr1d3/MCP_Servers/filesystem_mcp_server.py',
    'infrastructure': '/home/ov3rr1d3/MCP_Servers/infrastructure_mcp_server.py',
    'sysadmin': '/home/ov3rr1d3/MCP_Servers/sysadmin_mcp_server.py',
    'development': '/home/ov3rr1d3/MCP_Servers/development_mcp_server.py',
    'wifi_arsenal': '/home/ov3rr1d3/wifi_arsenal/wifi_arsenal_mcp_server.py',
}

class MCPServerConnection:
    """Connection to a single MCP server"""
    
    def __init__(self, name: str, script_path: str):
        self.name = name
        self.script_path = script_path
        self.process: Optional[subprocess.Popen] = None
        self.tools: List[Dict] = []
        self.message_id = 0
    
    def start(self) -> bool:
        """Start the MCP server process"""
        try:
            self.process = subprocess.Popen(
                ['python3', self.script_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Initialize the connection
            init_response = self._send_message({
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "operator", "version": "1.0.0"}
                }
            })
            
            if init_response and 'result' in init_response:
                # Send initialized notification
                self._send_notification({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized"
                })
                
                # Get tools list
                tools_response = self._send_message({
                    "jsonrpc": "2.0",
                    "id": self._next_id(),
                    "method": "tools/list",
                    "params": {}
                })
                
                if tools_response and 'result' in tools_response:
                    self.tools = tools_response['result'].get('tools', [])
                    return True
            
            return False
            
        except Exception as e:
            print(f"Failed to start MCP server {self.name}: {e}", file=sys.stderr)
            return False
    
    def stop(self):
        """Stop the MCP server process"""
        if self.process:
            self.process.terminate()
            self.process = None
    
    def _next_id(self) -> int:
        self.message_id += 1
        return self.message_id
    
    def _send_message(self, message: Dict) -> Optional[Dict]:
        """Send a message and wait for response"""
        if not self.process:
            return None
        
        try:
            msg_str = json.dumps(message) + '\n'
            self.process.stdin.write(msg_str)
            self.process.stdin.flush()
            
            # Read response
            response_line = self.process.stdout.readline()
            if response_line:
                return json.loads(response_line.strip())
            return None
            
        except Exception as e:
            print(f"MCP communication error ({self.name}): {e}", file=sys.stderr)
            return None
    
    def _send_notification(self, message: Dict):
        """Send a notification (no response expected)"""
        if not self.process:
            return
        
        try:
            msg_str = json.dumps(message) + '\n'
            self.process.stdin.write(msg_str)
            self.process.stdin.flush()
        except:
            pass
    
    def call_tool(self, tool_name: str, arguments: Dict) -> Dict:
        """Call a tool on this server"""
        response = self._send_message({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        })
        
        if response and 'result' in response:
            return response['result']
        elif response and 'error' in response:
            return {"content": [{"type": "text", "text": f"Error: {response['error']}"}], "isError": True}
        else:
            return {"content": [{"type": "text", "text": "No response from server"}], "isError": True}


class MCPClient:
    """Manages all MCP server connections"""
    
    def __init__(self):
        self.connections: Dict[str, MCPServerConnection] = {}
        self.tool_to_server: Dict[str, str] = {}  # Maps tool name to server name
    
    def connect_all(self, servers: Dict[str, str] = None) -> int:
        """Connect to all specified MCP servers, returns count of successful connections"""
        if servers is None:
            servers = MCP_SERVERS
        
        connected = 0
        for name, path in servers.items():
            if not Path(path).exists():
                print(f"MCP server not found: {path}", file=sys.stderr)
                continue
            
            conn = MCPServerConnection(name, path)
            if conn.start():
                self.connections[name] = conn
                
                # Map tools to this server
                for tool in conn.tools:
                    full_name = f"{name}:{tool['name']}"
                    self.tool_to_server[full_name] = name
                
                connected += 1
                print(f"Connected to MCP server: {name} ({len(conn.tools)} tools)")
            else:
                print(f"Failed to connect to MCP server: {name}")
        
        return connected
    
    def disconnect_all(self):
        """Disconnect from all servers"""
        for conn in self.connections.values():
            conn.stop()
        self.connections.clear()
        self.tool_to_server.clear()
    
    def get_all_tools(self) -> List[Dict]:
        """Get all tools from all connected servers, formatted for Claude API"""
        tools = []
        self.tool_to_server = {}  # Map full tool name to (server_name, original_tool_name)
        
        for server_name, conn in self.connections.items():
            for tool in conn.tools:
                full_name = f"{server_name}_{tool['name']}"
                self.tool_to_server[full_name] = (server_name, tool['name'])
                
                # Format for Claude API
                claude_tool = {
                    "name": full_name,
                    "description": f"[{server_name}] {tool.get('description', '')}",
                    "input_schema": tool.get('inputSchema', {"type": "object", "properties": {}})
                }
                tools.append(claude_tool)
        return tools
    
    def call_tool(self, tool_name: str, arguments: Dict) -> str:
        """Call a tool by its full name (server_toolname)"""
        # Use the mapping we built in get_all_tools
        if hasattr(self, 'tool_to_server') and tool_name in self.tool_to_server:
            server_name, actual_tool_name = self.tool_to_server[tool_name]
        else:
            # Fallback: try to match against known server names
            matched = False
            for srv_name in self.connections.keys():
                prefix = f"{srv_name}_"
                if tool_name.startswith(prefix):
                    server_name = srv_name
                    actual_tool_name = tool_name[len(prefix):]
                    matched = True
                    break
            
            if not matched:
                return f"Unknown tool: {tool_name}"
        
        if server_name not in self.connections:
            return f"Server not connected: {server_name}"
        
        result = self.connections[server_name].call_tool(actual_tool_name, arguments)
        
        # Extract text from result
        if 'content' in result:
            texts = []
            for item in result['content']:
                if item.get('type') == 'text':
                    texts.append(item.get('text', ''))
            return '\n'.join(texts)
        
        return str(result)


# Singleton instance
_mcp_client: Optional[MCPClient] = None

def get_mcp_client() -> MCPClient:
    """Get or create the MCP client singleton"""
    global _mcp_client
    if _mcp_client is None:
        _mcp_client = MCPClient()
        _mcp_client.connect_all()
    return _mcp_client

def shutdown_mcp_client():
    """Shutdown the MCP client"""
    global _mcp_client
    if _mcp_client:
        _mcp_client.disconnect_all()
        _mcp_client = None


if __name__ == '__main__':
    # Test the client
    client = MCPClient()
    connected = client.connect_all()
    print(f"\nConnected to {connected} servers")
    
    tools = client.get_all_tools()
    print(f"Total tools available: {len(tools)}")
    
    for tool in tools[:10]:
        print(f"  - {tool['name']}")
    
    if tools:
        print("\n... and more")
    
    # Test a simple tool call
    result = client.call_tool('infrastructure_system_info', {})
    print(f"\nTest call result:\n{result[:500]}...")
    
    client.disconnect_all()
