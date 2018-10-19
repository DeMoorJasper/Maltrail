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

Maltrail expects plugins to have a function named `plugin`, this function takes in two argument `packet` and `emit_event`, a plugin can emit as much events as it wants. However it should try to keep the amount of false positives to an absolute minimum.

Example:

```python
from core.enums import TRAIL
from core.events.Event import Event

# Define the plugin
def plugin(packet, emit_event):
    # log an event
    emit_event(Event(packet, TRAIL.IP, "this is a trail", "some info...", "reference"))
```

## packet

A packet is a processed IP packet with a little bit of extra metadata, which wasn't part of the original IP packet but got added by maltrail.

### Object keys

#### sec

#### usec

#### is_empty

`True` if the packet is empty `False` if it contains any data.

The packet processor filters empty packets out, so these will never reach a plugin.

#### localhost_ip

Metadat provided by Maltrail, setting the localhost_ip associated with the specified ip_version.

#### ip_version

ip version

#### ip_data

the raw ip packet

#### ip_header

the ip header

#### iph_length

the ip header length

#### protocol

the protocol

#### proto

the name of the protocol as defined by `core.enums`

#### src_ip

source ip

#### dst_ip

destination ip

#### src_port

source port

#### dst_port

destination port

#### tcp

This is only set in case this packet is a `tcp` packet. It contains a tuple with the tcp header data.

`(src_port, dst_port, seq_number, ack_number, data_offset_reserved, flags)`

#### udp

This is only set in case this packet is a `udp` packet. It contains a tuple with the udp header data.

`(src_port, dst_port)`

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
