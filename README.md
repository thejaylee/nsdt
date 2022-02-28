# Netgear Switch Discovery Tool

A simple CLI tool for interrogating networks to retrieve infomation from netgear managed switches.

Only read operations are supported thus far.

## Installation
Install required packages via `pip install -r requirements.txt` and then run `nsdt.py` from CLI.

### Usage

```
usage: nsdt.py [-h] [-l] [-i <num>] [-t <hex> [hex ...]] [--list-message-types]

NetGear Switch Discoverer

options:
  -h, --help            show this help message and exit
  -l                    list interfaces
  -i <num>              interface to use
  -t <hex> [hex ...]    message types to interrogate
  --list-message-types  list message types
```
