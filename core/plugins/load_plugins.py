import core.logger as logger

from core.plugins.plugin_utils import find_plugin
from core.plugins.plugin_utils import validate_plugin
from core.plugins.plugin_utils import load_plugin

def load_plugins(plugins):
    plugin_functions = []
    for plugin in plugins:
        plugin = find_plugin("plugins", plugin.strip())

        if not plugin:
            exit("plugin script '%s' not found" % plugin)
        
        filename = validate_plugin(plugin)

        try:
            plugin_tuple = load_plugin(filename, "plugin")
        except (ImportError, SyntaxError), msg:
            exit("unable to import plugin script '%s' (%s)" % (filename, msg))

        if not plugin_tuple:
            exit("missing function 'plugin(packet)' in plugin script '%s'" % filename)
            
        plugin_functions.append(plugin_tuple)
        logger.info("Plugin initialised:", plugin)

    return plugin_functions
