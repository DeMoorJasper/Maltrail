import sys
import re
import os
import inspect

from core.logger import log_info

def load_plugins(plugins):
    plugin_functions = []
    for plugin in plugins:
        plugin = plugin.strip()
        found = False

        for _ in (plugin, os.path.join("plugins", plugin), os.path.join("plugins", "%s.py" % plugin)):
            if os.path.isfile(_):
                plugin = _
                found = True
                break

        if not found:
            exit("plugin script '%s' not found" % plugin)
        else:
            dirname, filename = os.path.split(plugin)
            dirname = os.path.abspath(dirname)
            if not os.path.exists(os.path.join(dirname, '__init__.py')):
                exit("empty file '__init__.py' required inside directory '%s'" % dirname)

            if not filename.endswith(".py"):
                exit("plugin script '%s' should have an extension '.py'" % filename)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(
                    filename[:-3].encode(sys.getfilesystemencoding()))
            except (ImportError, SyntaxError), msg:
                exit("unable to import plugin script '%s' (%s)" %
                     (filename, msg))

            found = False
            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "plugin" and not set(inspect.getargspec(function).args) & set(("packet")):
                    found = True
                    plugin_functions.append((plugin, function))
                    function.func_name = module.__name__

            if not found:
                exit("missing function 'plugin(packet)' in plugin script '%s'" % filename)
            else:
                log_info("Plugin initialised:", plugin)

    return plugin_functions
