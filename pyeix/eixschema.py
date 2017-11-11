#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import json
import six
from six.moves.urllib.request import urlopen
from jsonschema import Draft4Validator
from .errors import CommonError
import os
import pkg_resources

ERR_EIXError = {'code': 500, 'title': 'EuroIX Error', 'more_info': ""}

ERR_EIXSchema = {
    'code': 500,
    'title': 'EuroIX Schema Error',
    'more_info': ("It's possible that the JSON schema used by the IX to export "
                  "its members list is not aligned with the one recognized by "
                  "this version of the program, or that it contains errors.")
}


class EIXError(CommonError):
    """EuroIX error"""

    def __init__(self, description=None):
        super(self.__class__, self).__init__(ERR_EIXError)
        self.error['description'] = description


class EIXSchemaError(CommonError):
    """EuroIX Schema Error"""

    def __init__(self, description=None):
        super(self.__class__, self).__init__(ERR_EIXSchema)
        self.error['description'] = description


class EuroIXSchema(object):
    """EuroIX JSON Schema abstraction"""
    schemas = {
        '0.4': 'ixp-member-list-0.4.schema.json',
        '0.5': 'ixp-member-list-0.5.schema.json',
        '0.6': 'ixp-member-list-0.6.schema.json'
    }

    def __init__(self, input=None, schema=None):
        self.raw_data = None
        self.timestamp = None
        self.version = None
        self.schema = None
        if input is not None:
            self.load_data(input, schema)

    def _load_schema(self, schema=None):
        if schema is not None and schema not in self.schemas:
            raise EIXError(
                "The requested version of the JSON schema is not known yet.")
        try:
            pkg_path = pkg_resources.resource_filename("pyeix", 'schema')
            with open("{}/{}".format(pkg_path, self.schemas[schema])) as data_file:
                self.schema = json.load(data_file)
        except:
            raise EIXError("Can't load the EuroIX Schema File")

    def load_data(self, input_object, schema=None):
        if isinstance(input_object, dict):
            self.raw_data = input_object
        elif isinstance(input_object, six.string_types):
            if input_object.startswith('http'):
                try:
                    response = urlopen(input_object)
                    raw = response.read().decode("utf-8")
                except Exception as e:
                    raise EIXError("Error while retrieving Euro-IX JSON file "
                                   "from {}: {}".format(input_object, str(e)))
            else:
                try:
                    with open(input_object) as data_file:
                        raw = data_file.read().decode('utf-8')
                except:
                    raise EIXError(
                        "Error reading file {}".format(input_object))
        else:
            raise EIXError("Error reading EIX json file.")

        if not self.raw_data:
            try:
                self.raw_data = json.loads(raw)
            except Exception as e:
                raise EIXError("Error while processing JSON data: {}".format(
                    str(e)))
        self.timestamp = self._get_item('timestamp', self.raw_data, str)
        self.version = self._get_item('version', self.raw_data, str)
        if schema is not None and self.version != schema:
            raise EIXSchemaError(
                'Requested and file schema version are not compliant.')
        schema_version = self.version if schema is None else schema
        self._load_schema(schema_version)
        self.validate_schema()

    def validate_schema(self):
        """validate schema"""
        if not Draft4Validator(self.schema).is_valid(self.raw_data):
            raise EIXSchemaError()
        return True

    @staticmethod
    def _check_type(v, vname, expected_type):
        if expected_type is str:
            expected_type_set = six.string_types
        else:
            expected_type_set = expected_type

        if not isinstance(v, expected_type_set):
            if expected_type is int and isinstance(
                    v, six.string_types) and v.isdigit():
                return int(v)

            raise EIXSchemaError("Invalid type for {} with value '{}': "
                                 "it is {}, should be {}".format(
                                     vname, v, str(type(v)), str(expected_type)))
        return v

    @staticmethod
    def _get_item(key, src, expected_type=None, optional=False):
        if key not in src:
            if optional:
                return None
            raise EIXSchemaError("Missing required item: {}".format(key))
        val = src[key]
        if expected_type:
            val = EuroIXSchema._check_type(val, key, expected_type)
        return val

    def _get_ixp(self, ixp_list, ixp_id):
        self._check_type(ixp_list, "ixp_list", list)
        ixp_found = False
        retval = None
        for ixp in ixp_list:
            self._check_type(ixp, "ixp", dict)
            if self._get_item("ixp_id", ixp, int) == ixp_id:
                ixp_found = True
                retval = ixp
                break
        if not ixp_found:
            raise EIXError("IXP ID {} not found".format(ixp_id))
        return retval

    def get_ixps(self):
        data = self.raw_data
        ixp_list = self._get_item("ixp_list", data, list)
        retval = []
        for ixp in ixp_list:
            self._check_type(ixp, "ixp", dict)
            addon = dict(
                ixp_id=self._get_item('ixp_id', ixp, int),
                ixf_id=self._get_item('ixf_id', ixp, int, True),
                shortname=self._get_item('shortname', ixp, str),
                name=self._get_item("name", ixp, str, True),
                country=self._get_item("country", ixp, str, True),
                url=self._get_item('url', ixp, str, True),
                stats_api=self._get_item('stats_api', ixp, str, True)
            )
            retval.append(addon)
        return retval

    def get_vlans(self, ixp_id=None):
        data = self.raw_data
        ixp_list = self._get_item("ixp_list", data, list)
        vlans = []
        for ixp in ixp_list:
            self._check_type(ixp, "ixp", dict)
            ixpid = self._get_item('ixp_id', ixp, int)
            if ixp_id is not None and ixpid != ixp_id:
                continue
            vlan_list = self._get_item('vlan', ixp, list, True)
            if vlan_list is None:
                vlan_list = []
            for vlan in vlan_list:
                vlan['ixp_id'] = ixpid
                vlans.append(vlan)
        retval = []

        def parse_ip(ip):
            if ip is None:
                return None
            prefix = self._get_item('prefix', ip, str, True)
            mask_length = self._get_item('mask_length', ip, int, True)
            if prefix is None or mask_length is None:
                return None
            return dict(prefix=prefix, mask_length=mask_length)

        for vlan in vlans:
            self._check_type(vlan, "vlan", dict)
            addon = dict(
                vlan_id=self._get_item('id', vlan, int),
                ixp_id=self._get_item('ixp_id', vlan, int),
                name=self._get_item('name', vlan, str, True),
                ipv4=parse_ip(self._get_item('ipv4', vlan, dict, True)),
                ipv6=parse_ip(self._get_item('ipv6', vlan, dict, True))
            )
            retval.append(addon)
        return retval

    def get_ixp_contacts(self, ixp_id):
        data = self.raw_data
        ixp_list = self._get_item("ixp_list", data, list)
        ixp = self._get_ixp(ixp_list, ixp_id)
        support = dict(
            type='support',
            email=self._get_item('support_email', ixp, str, True),
            phone=self._get_item('support_phone', ixp, str, True),
            contact_hours=self._get_item(
                'support_contact_hours', ixp, str, True),
        )
        emergency = dict(
            type='emergency',
            email=self._get_item('emergency_email', ixp, str, True),
            phone=self._get_item('emergency_phone', ixp, str, True),
            contact_hours=self._get_item(
                'emergency_contact_hours', ixp, str, True),
        )
        billing = dict(
            type='billing',
            email=self._get_item('billing_email', ixp, str, True),
            phone=self._get_item('billing_phone', ixp, str, True),
            contact_hours=self._get_item(
                'billing_contact_hours', ixp, str, True),
        )
        contacts = [support, emergency, billing]
        return contacts

    def get_ixp_switches(self, ixp_id):
        data = self.raw_data
        ixp_list = self._get_item("ixp_list", data, list)
        ixp = self._get_ixp(ixp_list, ixp_id)
        switch_list = self._get_item('switch', ixp, list, True)
        if switch_list is None:
            switch_list = []
        retval = []
        for sw in switch_list:
            self._check_type(sw, 'switch', dict)
            addon = dict(
                ixp_id=ixp_id,
                switch_id=self._get_item('id', sw, int, True),
                name=self._get_item('name', sw, str, True),
                colo=self._get_item('colo', sw, str, True),
                pdb_facility_id=self._get_item(
                    'pdb_facility_id', sw, int, True),
                city=self._get_item('city', sw, str, True),
                country=self._get_item('country', sw, str, True),
            )
            retval.append(addon)
        return retval

    def get_ixp_policies(self, ixp_id):
        data = self.raw_data
        ixp_list = self._get_item("ixp_list", data, list)
        ixp = self._get_ixp(ixp_list, ixp_id)
        return self._get_item('peering_policy_list', ixp, list, True)

    def get_members(self, ixp_id, vlan_id=None, rs_only=True):
        data = self.raw_data
        ixp_list = self._get_item("ixp_list", data, list)
        member_list = self._get_item('member_list', data, list)
        ixp = self._get_ixp(ixp_list, ixp_id)

        def parse_member(member):
            connection_list = self._get_item("connection_list", member, list)
            raw_client = []
            for connection in connection_list:
                client = {}
                self._check_type(connection, 'connection_list', dict)
                state = self._get_item('state', connection, str, True)
                if state is None:
                    state = 'active'
                connected_since = self._get_item(
                    'connected_since', connection, str, True)
                if self._get_item("ixp_id", connection, int) != ixp_id:
                    continue
                vlan_list = self._get_item("vlan_list", connection, list, True)
                if_list = self._get_item("if_list", connection, list, True)
                raw_vlan = {}
                for vlan in vlan_list or []:
                    self._check_type(vlan, 'vlan entry', dict)
                    vid = self._get_item('vlan_id', vlan, int, True)
                    if vlan_id is not None and vid != vlan_id:
                        continue
                    raw = raw_vlan[vid] if vid in raw_vlan else {}
                    for ipv in (4, 6):
                        ipver = "ipv{}".format(ipv)
                        ip_info = self._get_item(ipver, vlan, dict, True)
                        if ip_info is None:
                            continue
                        address = self._get_item("address", ip_info, str, True)
                        if address is None:
                            continue
                        routeserver = self._get_item(
                            "routeserver", ip_info, bool, True)
                        if rs_only and not routeserver:
                            continue
                        as_macro = self._get_item(
                            "as_macro", ip_info, str, True)
                        max_prefix = self._get_item(
                            "max_prefix", ip_info, int, True)
                        mac_addresses = self._get_item(
                            "mac_addresses", ip_info, list, True)
                        rawip = raw[ipver] if ipver in raw else []
                        rawip.append(dict(
                            address=address,
                            routeserver=routeserver,
                            as_macro=as_macro,
                            max_prefix=max_prefix,
                            mac_addresses=mac_addresses))
                        raw[ipver] = rawip
                    if raw != {}:
                        raw_vlan[vid] = raw
                if raw_vlan == {}:
                    continue  # entry without the vlan definition?
                raw_intf = []
                for intf in if_list or []:
                    self._check_type(intf, 'if_list entry', dict)
                    switch_id = self._get_item("switch_id", intf, int, True)
                    if_speed = self._get_item("if_speed", intf, int, True)
                    if_type = self._get_item("if_type", intf, str, True)
                    raw_intf.append(dict(
                        switch_id=switch_id,
                        if_speed=if_speed,
                        if_type=if_type
                    ))
                client['vlan_list'] = raw_vlan
                client['intf_list'] = raw_intf
                client['state'] = state
                client['connected_since'] = connected_since
                raw_client.append(client)
            return raw_client

        raw_members = []
        for member in member_list:
            self._check_type(member, 'member', dict)
            member_type = self._get_item('member_type', member, str, True)
            if member_type == 'routeserver':
                continue  # Member is a route server itself.
            new_member = parse_member(member)
            if new_member is None:
                continue
            raw = dict(
                asnum=self._get_item('asnum', member, int),
                name=self._get_item('name', member, str,
                                    True).encode('utf-8').strip(),
                member_type=member_type,
                url=self._get_item('url', member, str, True),
                peering_policy=self._get_item(
                    'peering_policy', member, str, True),
                peering_policy_url=self._get_item(
                    'peering_policy_url', member, str, True),
                member_since=self._get_item('member_since', member, str, True),
                connections=new_member
            )
            raw_members.append(raw)
        return raw_members

    def list_members(self, ixp_id=None, vlan_id=None):
        retval = []
        data = self.raw_data
        member_list = self._get_item('member_list', data, list)
        for member in member_list:
            name = self._get_item('name', member, str, True).encode('utf-8').strip()
            retval.append(name)
        return list(set(retval))

    def list_asns(self, ixp_id=None, vlan_id=None):
        retval = []
        data = self.raw_data
        member_list = self._get_item('member_list', data, list)
        for member in member_list:
            asnum = self._get_item('asnum', member, int)
            retval.append(asnum)
        return list(set(retval))

    def list_ip(self, proto='ipv4', ixp_id=None, vlan_id=None):
        """
        List IPs at IXP
        """
        assert proto == 'ipv4' or proto == 'ipv6'
        retval = []
        data = self.raw_data
        member_list = self._get_item('member_list', data, list)
        for member in member_list:
            connection_list = self._get_item("connection_list", member, list)
            for connection in connection_list:
                vlan_list = self._get_item("vlan_list", connection, list, True)
                for vlan in vlan_list:
                    if proto in vlan:
                        retval.append(vlan[proto]['address'])
        return list(set(retval))
