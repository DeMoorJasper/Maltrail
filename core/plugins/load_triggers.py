from core.logging.logger import log_info
from core.plugins.plugin_utils import find_plugin
from core.plugins.plugin_utils import validate_plugin
from core.plugins.plugin_utils import load_plugin

def load_triggers(triggers):
    trigger_functions = []
    for trigger in triggers:
        foundTrigger = find_plugin("triggers", trigger.strip())

        if not foundTrigger:
            exit("trigger script '%s' not found" % trigger)
        
        trigger = foundTrigger
        filename = validate_plugin(trigger)

        try:
            trigger_tuple = load_plugin(filename, "trigger")
        except (ImportError, SyntaxError), msg:
            exit("unable to import trigger script '%s' (%s)" % (filename, msg))

        if not trigger_tuple:
            exit("missing function 'trigger(event)' in trigger script '%s'" % filename)
            
        trigger_functions.append(trigger_tuple)
        log_info("Trigger initialised:", trigger)

    return trigger_functions
