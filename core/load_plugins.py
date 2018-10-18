import sys
import re
import os
import inspect

from core.logger import log_debug

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
            exit("[ERROR]: plugin script '%s' not found" % plugin)
        else:
            dirname, filename = os.path.split(plugin)
            dirname = os.path.abspath(dirname)
            if not os.path.exists(os.path.join(dirname, '__init__.py')):
                exit(
                    "[ERROR]: empty file '__init__.py' required inside directory '%s'" % dirname)

            if not filename.endswith(".py"):
                exit("[ERROR]: plugin script '%s' should have an extension '.py'" % filename)

            if dirname not in sys.path:
                sys.path.insert(0, dirname)

            try:
                module = __import__(
                    filename[:-3].encode(sys.getfilesystemencoding()))
            except (ImportError, SyntaxError), msg:
                exit("[ERROR]: unable to import plugin script '%s' (%s)" %
                     (filename, msg))

            found = False
            for name, function in inspect.getmembers(module, inspect.isfunction):
                if name == "plugin" and not set(inspect.getargspec(function).args) & set(("pkg")):
                    found = True
                    plugin_functions.append((plugin, function))
                    function.func_name = module.__name__

            if not found:
                exit("[ERROR]: missing function 'plugin(pkg)' in plugin script '%s'" % filename)
            else:
                log_debug("Plugin initialised:", plugin)

    return plugin_functions
