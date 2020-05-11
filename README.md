[![pypi](https://img.shields.io/pypi/v/someip.svg?style=flat-square)](https://pypi.org/project/someip)
[![python](https://img.shields.io/pypi/pyversions/someip.svg?style=flat-square)](https://pypi.org/project/someip)
[![docs](https://img.shields.io/readthedocs/pysomeip?style=flat-square)](https://pysomeip.readthedocs.io)
[![build](https://img.shields.io/github/workflow/status/afflux/pysomeip/Python%20package?style=flat-square)](https://github.com/afflux/pysomeip/actions?query=workflow%3A%22Python+package%22)
[![coverage](https://img.shields.io/codecov/c/github/afflux/pysomeip?style=flat-square)](https://codecov.io/gh/afflux/pysomeip)

pysomeip
========
A simple implementation of [SOME/IP](http://some-ip.com/), in Python 3.8+ with [asyncio](https://docs.python.org/3/library/asyncio.html).

Wire format building and parsing in `someip.header`, Service Discovery and socket logic in `someip.sd`. Refer to `tools/` for example CLI tools which should give a rough idea on how to use the API.

[API docs](https://pysomeip.readthedocs.io)

Missing Features
================
(Pull requests welcome!)

* SD options that are not referenced by entries are discarded.
* SubscribeAck and SubscribeNack is ignored
  * not signaled to applications
  * no way to handle MulticastEndpoint options for multicast event notifications
* subscription to TCP services is not supported
* subscription counter assignment
* SD messages to same hosts are not packed together
* probably other things
