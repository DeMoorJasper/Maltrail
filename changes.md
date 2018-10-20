# Changes

This isn't really a changelog, it's more of a blog type thing

## 18 Oct. 2018

### Plugin system

Removed old plugin system. Wrote a new one instead.
The new plugin system passes the entire packet to the plugin and allows it to trigger events as it pleases.
Thanks to this, I was able to extract half the code of sensor.py and split it across plugins. This increased the readability of this project a lot.

Thoughts:
- Not sure if creating a global `result_cache` was a good idea
- How about statistical heuristics, do that seperately or keep some kind of global heuristics state
  - This kind of already happens a bit, but it's very hacky and not very advanced. (Let's beat AI?)

TODO:
- Fix/Cleanup the UDP plugin
- Split up the plugins a bit more, they should be split based on attack, not protocol
- Write a bunch of docs that describe the plugin system in depth

### The package object

To allow sharing of processed packets I needed to create a new object, this became the package object. The package object contains ip's, ports and processed content for tcp and udp packets. (More info, see the docs)

Thoughts:
- I should have probably named it `packet`...

TODO:
- Rename Package to Packet?
- Move Package to it's own file
- Write docs for Package

### The Event object

Maltrail was using an event_tuple, (which is probably great for performance although I haven't benchmarked it) which isn't that good for usability as it took a lot of variables and none of it was documented.
Anyways I removed it in favor of an Event object, which uses the `Package` object to get most of it's information (as well as some trail data and attack info). This highly increases internal flexibility and usability for plugins.
This also allows us to create a log that includes more data without actually changing the plugin API.

TODO:
- Write docs for the event object

### Initial creation of the advanced docs

Thought it might be a good idea to document stuff for future reference, and to keep this changes blog fairly short.

### Add a capture from the HOWEST honeypot project

I've added a capture in captures that was recorded on my honeypot during the honeypot project of HOWEST. This should contain a bunch of attacks, unfortunately most of them are fairly basic attacks with tools. (and therefore easy to detect)

### Create logger

I don't like how Maltrail used print for everything and it kind of became weird as plugins run in threads. I made a logger that sort of replaces print.
Ideally I wanna get that file into `log.py`, but that would cause circular deps, so not sure what I'm gonna do against this. These files should eventually be combined as they should share some logic for log file creation and writing.

TODO:
- Combine `log.py` and `logger.py` without circular deps

## 19 Oct. 2018

### Restore UDP checks

I've updated the udp plugin to follow the latest api

### Rename Package => Packet

I've renamed Package to Packet as it's a Packet... also moved it into it's own file as I'm trying to make this code more structured

### Added event triggers

I've implemented event triggers, event triggers are a sort of plugin that triggers whenever an event gets logged from the regular plugins. These triggers can be used to log events to external servers and databases. As well as do custom logging on the local machine.

Thoughts:
- Replace event_log with a trigger, this would enable the user to have very fine-grained control as the user will be able to overwrite the default trigger as soon as the config key is set.

### Added emit_event to plugin function

The plugin function was relying on importing a function that triggers the event logging/processing. This isn't such a good idea as it might limit flexibility and plugins should rely as little as possible on the internal functions of maltrail. Therefore I passed the `emit_event function` as an argument into the `plugin function`.

## 20 Oct. 2018

### Refactor plugin API

I've refactored the plugin API again, now it's nearing it's final design stage. The future improvements are mainly in improving internal logic to improve accurracy and performance.

The plugin API is now as follows `def plugin(packet, config, trails)`, so it no longer contains an emit_event function as this wasn't such a good idea and might cause duplicate events or a lot of false positives.

The new API makes the plugin return the event, so it can only link one event to one packet. The internal plugin_runner/packet_handler should be responsible for filtering out the least accurate or relevant events.

TODO:
- Improve event to include explicit accuracy and severity