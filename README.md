# Network Scanner

A multithreaded TCP network scanner built in Python that identifies open ports and common services on a host or subnet.

## Features

* Scan a single IP or CIDR subnet
* Multithreaded port scanning
* Basic service detection
* Optional banner grabbing
* CSV and JSON export of results

## Example

```bash
python network_scanner.py 127.0.0.1 --ports 8000 --banner --json results.json
```

Example output:

```
Host: 127.0.0.1
Port 8000 | open | http-alt
```

## Technologies

* Python
* sockets
* threading
* argparse

## Note

For educational use only. Only scan systems you own or have permission to test.
