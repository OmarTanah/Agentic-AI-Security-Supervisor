from .wazuh_tools import get_wazuh_tools
from .block_tools import get_block_tools
from .report_tools import get_report_tools

def get_all_tools(db_manager, wazuh_config, policies, vt_api_key=None):
    tools = []
    tools.extend(get_wazuh_tools(db_manager, wazuh_config, vt_api_key=vt_api_key))
    tools.extend(get_block_tools(db_manager, wazuh_config, policies))
    tools.extend(get_report_tools(db_manager))
    return tools