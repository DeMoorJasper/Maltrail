import os
import sys
import inspect

def find_plugin(folder, plugin):
    for p in (plugin, os.path.join(folder, plugin), os.path.join(folder, "%s.py" % plugin)):
        if os.path.isfile(p):
            return p

def validate_plugin(plugin):
    dirname, filename = os.path.split(plugin)
    dirname = os.path.abspath(dirname)
    if not os.path.exists(os.path.join(dirname, '__init__.py')):
        exit("empty file '__init__.py' required inside directory '%s'" % dirname)

    if not filename.endswith(".py"):
        exit("script '%s' should have an extension '.py'" % filename)

    if dirname not in sys.path:
        sys.path.insert(0, dirname)

    return filename

def load_plugin(filename, function_name):
    module = __import__(filename[:-3].encode(sys.getfilesystemencoding()))
    
    for name, function in inspect.getmembers(module, inspect.isfunction):
        if name == function_name:
            function.func_name = module.__name__
            return (filename, function)