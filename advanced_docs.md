# CLI Options

## Custom config file

Define a custom configuration file

`-c {config file location}`

## Offline pcap File

Open pcap file for offline analysis

`-i {pcap file location}`

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

To configure Maltrail edit `maltrail.conf`

## Enabling plugins

Use the `PLUGINS` field to enable custom plugins

Example:

```txt
PLUGINS plugin1,plugin2
```

## Enabling triggers

Use the `TRIGGERS` field to enable custom event triggers

Example:

```txt
TRIGGERS trigger1,trigger2
```

# Plugins

Maltrail uses plugins to process packets and flag them as malicious/attacks. Maltrail comes built-in with a bunch of plugins for all kinds of attacks.

If you'd like to extend this functionality, create a plugin file inside the `plugins` folder.

## Defining the function

Maltrail expects plugins to have a function named `plugin`, this function takes in three argument `packet`, `config` and `trails`.

A plugin should only return a single event per run, as it takes in only one packet at a time. Maltrail will decide which event gets assigned to the package based on accuracy, severity and the plugin order (ordered from high priority -> low priority).

Example:

```python
from core.enums import TRAIL
from core.events.Event import Event

# Define the plugin
def plugin(packet, config, trails):
    # return an event
    return Event(packet, TRAIL.IP, "this is a trail", "some info...", "reference")
```

## packet

A packet is a processed IP packet with a little bit of extra metadata, which wasn't part of the original IP packet but got added by maltrail.

### Properties

#### sec

TODO: Figure out what this is exactly and document it

#### usec

TODO: Figure out what this is exactly and document it

#### ip

`ip` is the ip header data, it's an instance of impacket's [`IP` class](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/ImpactPacket.py#L757) this is a very powerfull library for retrieving header information quickly and easily without every plugin having to extract the data itself, or maltrail to re-implement all this logic.

## Event

An event is an attack or malicious packet maltrail detects. This gets processed by the triggers and logged to a file, server, ...

```Python
from core.events.Event import Event

Event(packet, trail_type, trail, info, reference)
```

### arguments

The Event constructor takes in 5 arguments

#### packet

The packet is the packet that is malicious/part of an attack. This should be an instance of `Packet`

```Python
from core.net.Packet import Packet

packet = Packet(*args)
```

#### trail_type

The trail type indicates what protocol the event belongs to.

So if it's a dns attack this should be `TRAIL.DNS`, if it's an http attack it should be `TRAIL.HTTP`, ...

`TRAIL` is part of the `core.enums` module.

```Python
from core.enums import TRAIL

trail_type = TRAIL.DNS
```

#### trail

`trail` is being used to group attacks. This is usually some kind of address: `ip` or `ip:port`, but it can be pretty much anything as long as it can be used to group attacks properly.

#### info

info describes the attack, this can be any kind of string. Describe the attack as good as possible, preferably keep it short.

#### reference

`reference` refers to the source of the trail list, this is usually the website the list originated from ex. `alienvault.com`.

However in case this isn't using any trail list you can also use the plugin name or a more generic name.

Some examples of generic names:
- `(signature)` for a packet that matches an attack signature
- `(heuristic)` for a heuristic detection
- `(statistical)` for a statistical anomaly
