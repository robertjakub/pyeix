# pyeix
A Python parser to the Euro-IX JSON schema

Install
=======

To install, execute: [in progress]

```
pip install pyeix
```

Documentation
=============

### Import Euro-IX Schema JSON
Import an IXP schema json, given a source URL to the JSON schema [or loaded dict]
```python
>>> from pyeix import EuroIXSchema
>>> eixschema = EuroIXSchema("https://www.bcix.de/ixp/api/v4/member-export/ixf/0.6")
```

### List IXPs
```python
>>> eixschema.list_ixps()
[{'name': u'BCIX Management GmbH', 'url': u'https://www.bcix.de/', 'country': u'DE', 'shortname': u'BCIX', 'ixf_id': 21, 'stats_api': None, 'ixp_id': 1}]
```

### List Vlans 
```python
>>> eixschema.list_vlans()
[{'name': u'BCIX Peering LAN', 'ipv6': {'prefix': u'2001:7f8:19:1::', 'mask_length': 64}, 'ixp_id': 1, 'vlan_id': 1, 'ipv4': {'prefix': u'193.178.185.0', 'mask_length': 25}}]
```

### List data by Network Name
```python
>>> eixschema.list_members()
['Aixit', 'LWLcom GmbH', 'EXARING AG', 'Console Network Solutions', 'CBXNET',...]
```

### List data by ASN 
```python
>>> eixschema.list_asns()
[58243, 25220, 35205, 15366, 15169, 8075, 48173, 3216,...]
```

### List data by IP
```python
>>> eixschema.list_ip('ipv4')
[u'193.178.185.101', u'193.178.185.100', u'193.178.185.103',...]
```

### List data by IPv6
```python
>>> eixschema.list_ip('ipv6')
[u'2001:7f8:19:1::3417:1', u'2001:7f8:19:1::8985:1', u'2001:7f8:19:1::b599:1',...]
```

License
======

Copyright 2017 project2

Licensed under the The MIT License (MIT)