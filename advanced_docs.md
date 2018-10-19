# CLI Options

## Custom config file

Define a custom configuration file

`-c {config file location}`

## Offline pcap File

Open pcap file for offline analysis

`-i {pcap file location}`

## Custom plugins

To load additional plugins from the cli

`-p {plugins}`

## Console

print events to console (too)

`--console`

## Disable dynamic trail updates

disable (online) trail updates

`--no-updates`

## Debug

Enable debug mode

`--debug`

# Configuring

To configure Maltrail edit core/settings.py

## Enabling plugins

Use the `plugins` field to enable third party plugins

Example:

```txt
plugins plugin1,plugin2
```

# Extendability

You can extend Maltrail by adding a plugin in the plugins folder (to enable the plugins, see the config reference)

## Defining the function

Maltrail expects plugins to have one function named `plugin`, this function takes in one argument `packet` and can log as much events as it wants.

Example:

```python
from core.enums import TRAIL
from core.log import log_event
from core.log import Event

# Define the plugin
def plugin(packet):
    # log an event
    log_event(Event(packet, TRAIL.IP, "this is a trail", "some info...", "reference"))
```

## packet

TODO: Explain packet in detail

## What are events?

TODO: Explain events

## Logging events

TODO: Explain how to log events