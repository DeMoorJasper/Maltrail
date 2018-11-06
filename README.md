# Maltrail, modified for easy extendability

This repo is a clone of [Maltrail](https://github.com/stamparm/Maltrail), this clone aims to create a more extandable, simplified, cleaner and advanced version of this amazing IDS. By making extandability and clean API's a priority.

This clone also tries to create a more advanced dashboard and streamline the core code to only need the bare minimum to work, with every attack specific and logging specific code extracted into plugins/extensions.

# Installation

## Setup sensor

```shell
sudo apt-get install git python-pcapy
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python get-pip.py
pip install impacket
git clone https://github.com/DeMoorJasper/maltrail.git
cd maltrail
sudo python sensor.py
```

# Documentation

You can mainly find documentation in the original repo for now. [Maltrail](https://github.com/stamparm/Maltrail)

## License

This project is licensed under MIT.

Original Maltrail was written by [`@stamparm`](https://github.com/stamparm)

This clone is written/maintained by [`@DeMoorJasper`](https://github.com/DeMoorJasper)