# Copyright 2015.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import uuid
import logging
import netaddr

from vnc_api import vnc_api
from vnc_api import exceptions as vnc_exc

import neutron_plugin_contrail.plugins.opencontrail.vnc_client.contrail_res_handler as res_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client.contrail_res_handler import ContrailResourceHandler
import neutron_plugin_contrail.plugins.opencontrail.vnc_client.vn_res_handler as vn_handler
from neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_base import NEUTRON_CONTRAIL_PREFIX


LOG = logging.getLogger(__name__)
ROUTE_TABLE_NAME_PREFIX = NEUTRON_CONTRAIL_PREFIX + '_RT'


class SubnetMixin(object):
    @staticmethod
    def get_subnet_dict(subnet_obj, vn_obj):
        pass

    @staticmethod
    def _subnet_vnc_get_key(subnet_vnc, net_id):
        pfx = subnet_vnc.subnet.get_ip_prefix()
        pfx_len = subnet_vnc.subnet.get_ip_prefix_len()

        network = netaddr.IPNetwork('%s/%s' % (pfx, pfx_len))
        return '%s %s/%s' % (net_id, str(network.ip), pfx_len)

    @staticmethod
    def _subnet_network(subnet_vnc):
        pfx = subnet_vnc.subnet.get_ip_prefix()
        pfx_len = subnet_vnc.subnet.get_ip_prefix_len()
        return netaddr.IPNetwork('%s/%s' % (pfx, pfx_len))

    def subnet_cidr_overlaps(self, subnet1, subnet2):
        cidr1 = self._subnet_network(subnet1)
        cidr2 = self._subnet_network(subnet2)
        return cidr1.first <= cidr2.last and cidr2.first <= cidr1.last

    def _subnet_vnc_read_mapping(self, id=None, key=None):
        if id:
            try:
                subnet_key = self._vnc_lib.kv_retrieve(id)
            except vnc_exc.NoIdError:
                self._raise_contrail_exception('SubnetNotFound',
                                               subnet_id=id,
                                               resource='subnet')
            return subnet_key

        if key:
            try:
                subnet_id = self._vnc_lib.kv_retrieve(key)
            except vnc_exc.NoIdError:
                subnet_id = None
            return subnet_id

    def get_vn_obj_for_subnet_id(self, subnet_id):
        subnet_key = self._vnc_lib.kv_retrieve(subnet_id)
        net_uuid = subnet_key.split(' ')[0]
        return self._resource_get(id=net_uuid)

    def _subnet_read(self, subnet_key=None, subnet_id=None):
        if not subnet_key:
            subnet_key = self._vnc_lib.kv_retrieve(subnet_id)

        net_uuid = subnet_key.split(' ')[0]
        try:
            vn_obj = self._resource_get(id=net_uuid)
        except vnc_exc.NoIdError:
            return None

        ipam_refs = vn_obj.get_network_ipam_refs()

        # TODO() scope for optimization
        for ipam_ref in ipam_refs or []:
            subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnet_vncs:
                if self._subnet_vnc_get_key(subnet_vnc,
                                            net_uuid) == subnet_key:
                    return subnet_vnc

    def _get_allocation_pools_dict(self, alloc_objs, gateway_ip, cidr):
        allocation_pools = []
        for alloc_obj in alloc_objs or []:
            first_ip = alloc_obj.get_start()
            last_ip = alloc_obj.get_end()
            alloc_dict = {'start': first_ip, 'end': last_ip}
            allocation_pools.append(alloc_dict)

        if not allocation_pools:
            if gateway_ip and (int(
                    netaddr.IPNetwork(gateway_ip).network) == int(
                    netaddr.IPNetwork(cidr).network + 1)):
                first_ip = str(netaddr.IPNetwork(cidr).network + 2)
            else:
                first_ip = str(netaddr.IPNetwork(cidr).network + 1)
            if gateway_ip and (int(
                    netaddr.IPNetwork(gateway_ip).network) == int(
                    netaddr.IPNetwork(cidr).broadcast - 1)):
                last_ip = str(netaddr.IPNetwork(cidr).broadcast - 2)
            else:
                last_ip = str(netaddr.IPNetwork(cidr).broadcast - 1)

            cidr_pool = {'start': first_ip, 'end': last_ip}
            allocation_pools.append(cidr_pool)

        return allocation_pools

    @staticmethod
    def get_vn_subnets(vn_obj):
        """Returns a list of dicts of subnet-id:cidr of a vn."""
        ret_subnets = []

        ipam_refs = vn_obj.get_network_ipam_refs()
        for ipam_ref in ipam_refs or []:
            subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnet_vncs:
                subnet_id = subnet_vnc.subnet_uuid
                cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                  subnet_vnc.subnet.get_ip_prefix_len())
                ret_subnets.append({'id': subnet_id, 'cidr': cidr})

        return ret_subnets

    @staticmethod
    def _check_ip_matches_version(item, version):
        if isinstance(item, list):
            for i in item:
                SubnetMixin._check_ip_matches_version(i, version)
            return

        if netaddr.IPNetwork(item).version != version:
            ContrailResourceHandler._raise_contrail_exception(
                'BadRequest', resource='subnet',
                msg='Invalid IP address version')

    @staticmethod
    def _subnet_neutron_to_vnc(subnet_q):
        if not subnet_q.get('cidr'):
            ContrailResourceHandler._raise_contrail_exception(
                'BadRequest', msg='cidr is empty',
                resource='subnet')

        cidr = netaddr.IPNetwork(subnet_q['cidr'])
        pfx = str(cidr.network)
        pfx_len = int(cidr.prefixlen)
        if pfx_len == 0 and cidr.version == 4:
            ContrailResourceHandler._raise_contrail_exception(
                'BadRequest',
                resource='subnet', msg="Invalid prefix len")
        if cidr.version != 4 and cidr.version != 6:
            ContrailResourceHandler._raise_contrail_exception(
                'BadRequest',
                resource='subnet', msg='Unknown IP family')
        elif cidr.version != int(subnet_q['ip_version']):
            msg = ("cidr '%s' does not match the ip_version '%s'"
                   % (subnet_q['cidr'], subnet_q['ip_version']))
            ContrailResourceHandler._raise_contrail_exception(
                'InvalidInput', error_message=msg, resource='subnet')

        if 'gateway_ip' in subnet_q:
            default_gw = subnet_q['gateway_ip']
            gw_ip_obj = netaddr.IPAddress(default_gw)
            if default_gw != '0.0.0.0':
                if gw_ip_obj not in cidr or gw_ip_obj.words[-1] == 255 or (
                        gw_ip_obj.words[-1] == 0):
                    ContrailResourceHandler._raise_contrail_exception(
                        'BadRequest', resource='subnet',
                        msg="Invalid Gateway ip address")
        else:
            # Assigned first+1 from cidr
            default_gw = str(netaddr.IPAddress(cidr.first + 1))

        if cidr.version == 4 and 'ipv6_address_mode' in subnet_q:
            ContrailResourceHandler._raise_contrail_exception(
                'BadRequest', resource='subnet',
                msg="Invalid address mode with version")

        if 'allocation_pools' in subnet_q:
            alloc_pools = subnet_q['allocation_pools']
            alloc_cidrs = []
            for pool in alloc_pools:
                try:
                    ip_start = netaddr.IPAddress(pool['start'])
                    ip_end = netaddr.IPAddress(pool['end'])
                except netaddr.core.AddrFormatError:
                    ContrailResourceHandler._raise_contrail_exception(
                        'BadRequest', resource='subnet',
                        msg="Invalid IP address in allocation pool")
                if ip_start >= ip_end:
                    ContrailResourceHandler._raise_contrail_exception(
                        'BadRequest', resource='subnet',
                        msg='Invalid address in allocation pool')

                if ip_start not in cidr or ip_end not in cidr:
                    ContrailResourceHandler._raise_contrail_exception(
                        'BadRequest', resource='subnet',
                        msg="Pool addresses not in subnet range")
                # Check if the pool overlaps with other pools
                for rng in alloc_cidrs:
                    if rng['start'] <= ip_start and ip_end <= rng['end']:
                        ContrailResourceHandler._raise_contrail_exception(
                            'BadRequest', resource='subnet',
                            msg='Pool addresses invalid')
                    elif (rng['start'] >= ip_start and (
                            rng['start'] <= ip_end)) or (
                                rng['end'] >= ip_start and (
                                    rng['end'] <= ip_end)):
                        ContrailResourceHandler._raise_contrail_exception(
                            'OverlappingAllocationPools',
                            pool_2="%s-%s" % (ip_start, ip_end),
                            pool_1="%s-%s" % (rng['start'], rng['end']),
                            subnet_cidr=str(cidr))
                alloc_cidrs.append({'start': ip_start, 'end': ip_end})

            gw_ip_obj = netaddr.IPAddress(default_gw)
            for rng in alloc_cidrs:
                st = rng['start']
                end = rng['end']
                if st <= gw_ip_obj and end >= gw_ip_obj:
                    ContrailResourceHandler._raise_contrail_exception(
                        'GatewayConflictWithAllocationPools',
                        ip_address=default_gw,
                        pool=str(cidr),
                        msg='Gw ip is part of allocation pools')

        else:
            # Assigned by address manager
            alloc_pools = None

        dhcp_option_list = None
        if 'dns_nameservers' in subnet_q and subnet_q['dns_nameservers']:
            dhcp_options = []
            dns_servers = " ".join(subnet_q['dns_nameservers'])
            if dns_servers:
                dhcp_options.append(vnc_api.DhcpOptionType(
                    dhcp_option_name='6', dhcp_option_value=dns_servers))
            if dhcp_options:
                dhcp_option_list = vnc_api.DhcpOptionsListType(dhcp_options)

        host_route_list = None
        if 'host_routes' in subnet_q and subnet_q['host_routes']:
            host_routes = []
            for host_route in subnet_q['host_routes']:
                SubnetMixin._check_ip_matches_version(
                    [host_route['destination'], host_route['nexthop']],
                    cidr.version)

                host_routes.append(vnc_api.RouteType(
                    prefix=host_route['destination'],
                    next_hop=host_route['nexthop']))
            if host_routes:
                host_route_list = vnc_api.RouteTableType(host_routes)

        if 'enable_dhcp' in subnet_q:
            dhcp_config = subnet_q['enable_dhcp']
        else:
            dhcp_config = None
        sn_name = subnet_q.get('name')
        subnet_vnc = vnc_api.IpamSubnetType(
            subnet=vnc_api.SubnetType(pfx, pfx_len),
            default_gateway=default_gw,
            enable_dhcp=dhcp_config,
            dns_nameservers=None,
            allocation_pools=alloc_pools,
            addr_from_start=True,
            dhcp_option_list=dhcp_option_list,
            host_routes=host_route_list,
            subnet_name=sn_name,
            subnet_uuid=str(uuid.uuid4()))

        return subnet_vnc

    def _subnet_vnc_to_neutron(self, subnet_vnc, vn_obj, ipam_fq_name,
                               fields=None):
        sn_q_dict = {}
        sn_name = subnet_vnc.get_subnet_name()
        if sn_name is not None:
            sn_q_dict['name'] = sn_name
        else:
            sn_q_dict['name'] = ''
        sn_q_dict['tenant_id'] = self._project_id_vnc_to_neutron(
            vn_obj.parent_uuid)
        sn_q_dict['network_id'] = vn_obj.uuid
        sn_q_dict['ipv6_ra_mode'] = None
        sn_q_dict['ipv6_address_mode'] = None

        cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                          subnet_vnc.subnet.get_ip_prefix_len())
        sn_q_dict['cidr'] = cidr
        sn_q_dict['ip_version'] = netaddr.IPNetwork(cidr).version  # 4 or 6

        # read from useragent kv only for old subnets created
        # before schema had uuid in subnet
        sn_id = subnet_vnc.subnet_uuid
        if not sn_id:
            subnet_key = self._subnet_vnc_get_key(subnet_vnc, vn_obj.uuid)
            sn_id = self._subnet_vnc_read_mapping(
                id=subnet_vnc.subnet_uuid, key=subnet_key)

        sn_q_dict['id'] = sn_id

        if subnet_vnc.default_gateway != '0.0.0.0':
            sn_q_dict['gateway_ip'] = subnet_vnc.default_gateway
        else:
            sn_q_dict['gateway_ip'] = None

        sn_q_dict['allocation_pools'] = self._get_allocation_pools_dict(
            subnet_vnc.get_allocation_pools(), sn_q_dict['gateway_ip'], cidr)

        sn_q_dict['enable_dhcp'] = subnet_vnc.get_enable_dhcp()

        nameserver_dict_list = list()
        dhcp_option_list = subnet_vnc.get_dhcp_option_list()
        if dhcp_option_list:
            for dhcp_option in dhcp_option_list.dhcp_option or []:
                if dhcp_option.get_dhcp_option_name() == '6':
                    dns_servers = dhcp_option.get_dhcp_option_value().split()
                    for dns_server in dns_servers:
                        nameserver_dict_list.append(dns_server)
        sn_q_dict['dns_nameservers'] = nameserver_dict_list

        host_route_dict_list = list()
        host_routes = subnet_vnc.get_host_routes()
        if host_routes:
            for host_route in host_routes.route or []:
                host_route_entry = {'destination': host_route.get_prefix(),
                                    'nexthop': host_route.get_next_hop()}
                host_route_dict_list.append(host_route_entry)
        sn_q_dict['host_routes'] = host_route_dict_list

        if vn_obj.is_shared:
            sn_q_dict['shared'] = True
        else:
            sn_q_dict['shared'] = False

        if fields:
            sn_q_dict = self._filter_res_dict(sn_q_dict, fields)
        return sn_q_dict

    def _build_subnet_host_routes(self, subnet_q, cidr_version):
        host_routes = []
        if subnet_q.get('host_routes') is not None:
            for host_route in subnet_q['host_routes']:
                self._check_ip_matches_version(
                    [host_route['destination'], host_route['nexthop']],
                    cidr_version)
                host_routes.append(vnc_api.RouteType(
                    prefix=host_route['destination'],
                    next_hop=host_route['nexthop']))
        return host_routes

    def _apply_subnet_host_routes(self, subnet_q, subnet_vnc, subnet_cidr, cidr_version, vn_obj):
        host_routes = self._build_subnet_host_routes(subnet_q, cidr_version)
        if host_routes:
            subnet_vnc.set_host_routes(vnc_api.RouteTableType(host_routes))
        else:
            subnet_vnc.set_host_routes(None)
        if self._kwargs.get('apply_subnet_host_routes', False):
            subnet_hr_handler = SubnetHostRoutesHandler(self._vnc_lib)
            subnet_hr_handler.sync_routes(vn_obj, subnet_vnc.subnet_uuid, subnet_cidr, host_routes)


class SubnetCreateHandler(res_handler.ResourceCreateHandler, SubnetMixin):

    def _get_netipam_obj(self, ipam_fq_name=None, vn_obj=None):
        if ipam_fq_name:
            domain_name, project_name, ipam_name = ipam_fq_name

            domain_obj = vnc_api.Domain(domain_name)
            project_obj = vnc_api.Project(project_name, domain_obj)
            netipam_obj = vnc_api.NetworkIpam(ipam_name, project_obj)
            return netipam_obj

        if vn_obj:
            try:
                ipam_fq_name = vn_obj.get_fq_name()[:-1]
                ipam_fq_name.append('default-network-ipam')
                netipam_obj = self._vnc_lib.network_ipam_read(
                    fq_name=ipam_fq_name)
            except vnc_exc.NoIdError:
                netipam_obj = vnc_api.NetworkIpam()
            return netipam_obj

    def resource_create(self, context, subnet_q):
        net_id = subnet_q['network_id']
        vn_obj = self._resource_get(id=net_id)
        ipam_fq_name = subnet_q.get('ipam_fq_name')
        netipam_obj = self._get_netipam_obj(ipam_fq_name,
                                            vn_obj)
        if not ipam_fq_name:
            ipam_fq_name = netipam_obj.get_fq_name()

        subnet_vnc = self._subnet_neutron_to_vnc(subnet_q)
        subnet_key = self._subnet_vnc_get_key(subnet_vnc, net_id)
        subnet_cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                 subnet_vnc.subnet.get_ip_prefix_len())
        cidr_version = netaddr.IPNetwork(subnet_cidr).version

        # Locate list of subnets to which this subnet has to be appended
        net_ipam_ref = None
        ipam_refs = vn_obj.get_network_ipam_refs()
        for ipam_ref in ipam_refs or []:
            if ipam_ref['to'] == ipam_fq_name:
                net_ipam_ref = ipam_ref
                break

        if not net_ipam_ref:
            # First link from net to this ipam
            vnsn_data = vnc_api.VnSubnetsType([subnet_vnc])
            vn_obj.add_network_ipam(netipam_obj, vnsn_data)
        else:  # virtual-network already linked to this ipam
            for subnet in net_ipam_ref['attr'].get_ipam_subnets():
                if self.subnet_cidr_overlaps(subnet_vnc, subnet):
                    existing_sn_id = self._subnet_vnc_read_mapping(
                        key=self._subnet_vnc_get_key(subnet, net_id))
                    # duplicate !!
                    msg = ("Cidr %s overlaps with another subnet of subnet %s"
                           ) % (subnet_q['cidr'], existing_sn_id)
                    self._raise_contrail_exception(
                        'BadRequest', resource='subnet', msg=msg)
            vnsn_data = net_ipam_ref['attr']
            vnsn_data.ipam_subnets.append(subnet_vnc)
            # TODO(): Add 'ref_update' API that will set this field
            vn_obj._pending_field_updates.add('network_ipam_refs')
        self._resource_update(vn_obj)

        # Read in subnet from server to get updated values for gw etc.
        subnet_vnc = self._subnet_read(subnet_key)
        self._apply_subnet_host_routes(subnet_q, subnet_vnc, subnet_cidr,
                                       cidr_version, vn_obj)
        subnet_info = self._subnet_vnc_to_neutron(subnet_vnc, vn_obj,
                                                  ipam_fq_name)

        return subnet_info


class SubnetDeleteHandler(res_handler.ResourceDeleteHandler, SubnetMixin):

    def resource_delete(self, context, subnet_id):
        subnet_key = self._subnet_vnc_read_mapping(id=subnet_id)
        net_id = subnet_key.split()[0]

        vn_obj = self._resource_get(id=net_id)
        ipam_refs = vn_obj.get_network_ipam_refs()
        for ipam_ref in ipam_refs or []:
            orig_subnets = ipam_ref['attr'].get_ipam_subnets()
            new_subnets = [subnet_vnc for subnet_vnc in orig_subnets
                           if self._subnet_vnc_get_key(
                               subnet_vnc, net_id) != subnet_key]
            if len(orig_subnets) != len(new_subnets):
                # matched subnet to be deleted
                ipam_ref['attr'].set_ipam_subnets(new_subnets)
                vn_obj._pending_field_updates.add('network_ipam_refs')
                try:
                    self._resource_update(vn_obj)
                except vnc_exc.RefsExistError:
                    self._raise_contrail_exception(
                        'SubnetInUse', subnet_id=subnet_id,
                        resource='subnet')


class SubnetGetHandler(res_handler.ResourceGetHandler, SubnetMixin):
    resource_list_method = 'virtual_networks_list'
    resource_get_method = 'virtual_network_read'

    def resource_get(self, context, subnet_id, fields=None):
        subnet_key = self._subnet_vnc_read_mapping(id=subnet_id)
        net_id = subnet_key.split()[0]

        try:
            vn_obj = self._resource_get(id=net_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception(
                'SubnetNotFound', subnet_id=subnet_id, resource='subnet')

        ipam_refs = vn_obj.get_network_ipam_refs()
        for ipam_ref in ipam_refs or []:
            subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnet_vncs:
                if self._subnet_vnc_get_key(subnet_vnc, net_id) == subnet_key:
                    ret_subnet_q = self._subnet_vnc_to_neutron(
                        subnet_vnc, vn_obj, ipam_ref['to'], fields=fields)
                    return ret_subnet_q

        return {}

    def resource_count(self, context, filters):
        subnets_info = self.resource_list(context, filters)
        return len(subnets_info)

    def _get_subnet_list_after_apply_filter_(self, vn_list, filters,
                                             fields=None):
        ret_subnets = []
        ret_dict = {}
        for vn_obj in vn_list:
            if vn_obj.uuid in ret_dict:
                continue
            ret_dict[vn_obj.uuid] = 1

            ipam_refs = vn_obj.get_network_ipam_refs()
            for ipam_ref in ipam_refs or []:
                subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
                for subnet_vnc in subnet_vncs:
                    sn_info = self._subnet_vnc_to_neutron(
                        subnet_vnc, vn_obj, ipam_ref['to'])
                    sn_id = sn_info['id']
                    sn_proj_id = sn_info['tenant_id']
                    sn_net_id = sn_info['network_id']
                    sn_name = sn_info['name']

                    if (filters and 'shared' in filters and
                            filters['shared'][0]):
                        if not vn_obj.is_shared:
                            continue
                    elif filters:
                        if not self._filters_is_present(filters, 'id',
                                                        sn_id):
                            continue
                        if not self._filters_is_present(filters,
                                                        'tenant_id',
                                                        sn_proj_id):
                            continue
                        if not self._filters_is_present(filters,
                                                        'network_id',
                                                        sn_net_id):
                            continue
                        if not self._filters_is_present(filters,
                                                        'name',
                                                        sn_name):
                            continue
                        if not self._filters_is_present(filters,
                                                        'ip_version',
                                                        sn_info['ip_version']):
                            continue
                    if fields:
                        sn_info = self._filter_res_dict(sn_info, fields)
                    ret_subnets.append(sn_info)

        return ret_subnets

    def resource_list(self, context, filters, fields=None):
        vn_get_handler = vn_handler.VNetworkGetHandler(self._vnc_lib)
        all_vn_objs = []
        if filters and 'id' in filters:
            # required subnets are specified,
            # just read in corresponding net_ids
            net_ids = []
            for subnet_id in filters['id']:
                subnet_key = self._subnet_vnc_read_mapping(id=subnet_id)
                net_id = subnet_key.split()[0]
                net_ids.append(net_id)

            all_vn_objs.extend(vn_get_handler.get_vn_obj_list(
                obj_uuids=net_ids, detail=True))
        else:
            if not context['is_admin']:
                proj_id = context['tenant']
            else:
                proj_id = None
            vn_objs = vn_get_handler.get_vn_list_project(proj_id)
            all_vn_objs.extend(vn_objs)
            vn_objs = vn_get_handler.vn_list_shared()
            all_vn_objs.extend(vn_objs)

        return self._get_subnet_list_after_apply_filter_(all_vn_objs, filters,
                                                         fields=fields)


class SubnetUpdateHandler(res_handler.ResourceUpdateHandler, SubnetMixin):
    resource_update_method = 'virtual_network_update'

    def _subnet_update(self, subnet_q, subnet_id, vn_obj, subnet_vnc,
                       ipam_ref, apply_subnet_host_routes=False):
        subnet_cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                 subnet_vnc.subnet.get_ip_prefix_len())
        cidr_version = netaddr.IPNetwork(subnet_cidr).version
        if subnet_q.get('name') is not None:
            subnet_vnc.set_subnet_name(subnet_q['name'])

        if subnet_q.get('gateway_ip') is not None:
            subnet_vnc.set_default_gateway(subnet_q['gateway_ip'])

        if subnet_q.get('enable_dhcp') is not None:
            subnet_vnc.set_enable_dhcp(subnet_q['enable_dhcp'])

        if subnet_q.get('dns_nameservers') is not None:
            dhcp_options = []
            dns_servers = " ".join(subnet_q['dns_nameservers'])
            self._check_ip_matches_version(subnet_q['dns_nameservers'],
                                           cidr_version)
            if dns_servers:
                dhcp_options.append(vnc_api.DhcpOptionType(
                    dhcp_option_name='6', dhcp_option_value=dns_servers))
            if dhcp_options:
                subnet_vnc.set_dhcp_option_list(vnc_api.DhcpOptionsListType(
                    dhcp_options))
            else:
                subnet_vnc.set_dhcp_option_list(None)

        self._apply_subnet_host_routes(subnet_q, subnet_vnc, subnet_cidr,
                                       cidr_version, vn_obj)

        vn_obj._pending_field_updates.add('network_ipam_refs')
        self._resource_update(vn_obj)
        ret_subnet_q = self._subnet_vnc_to_neutron(
            subnet_vnc, vn_obj, ipam_ref['to'])

        return ret_subnet_q

    def resource_update(self, context, subnet_id, subnet_q):
        apply_subnet_host_routes = self._kwargs.get(
            'apply_subnet_host_routes', False)
        if 'gateway_ip' in subnet_q:
            if subnet_q['gateway_ip'] is not None:
                self._raise_contrail_exception(
                    'BadRequest', resource='subnet',
                    msg="update of gateway is not supported")

        if 'allocation_pools' in subnet_q:
            if subnet_q['allocation_pools'] is not None:
                self._raise_contrail_exception(
                    'BadRequest', resource='subnet',
                    msg="update of allocation_pools is not allowed")

        subnet_key = self._subnet_vnc_read_mapping(id=subnet_id)
        net_id = subnet_key.split()[0]
        vn_obj = self._resource_get(id=net_id)
        ipam_refs = vn_obj.get_network_ipam_refs()
        for ipam_ref in ipam_refs or []:
            subnets = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnets:
                if self._subnet_vnc_get_key(
                        subnet_vnc,
                        net_id) == subnet_key:
                    return self._subnet_update(
                        subnet_q, subnet_id, vn_obj, subnet_vnc, ipam_ref,
                        apply_subnet_host_routes=apply_subnet_host_routes)

        return {}


class SubnetHostRoutesHandler(ContrailResourceHandler,
                              SubnetMixin):

    @staticmethod
    def get_host_prefixes(host_routes, subnet_cidr):
        """This function returns the host prefixes.

        Eg. If host_routes have the below routes
           ---------------------------
           |destination   | next hop  |
           ---------------------------
           |  10.0.0.0/24 | 8.0.0.2   |
           |  12.0.0.0/24 | 10.0.0.4  |
           |  14.0.0.0/24 | 12.0.0.23 |
           |  16.0.0.0/24 | 8.0.0.4   |
           |  15.0.0.0/24 | 16.0.0.2  |
           |  20.0.0.0/24 | 8.0.0.12  |
           ---------------------------
           subnet_cidr is 8.0.0.0/24

           This function returns the dictionary
           '8.0.0.2' : ['10.0.0.0/24', '12.0.0.0/24', '14.0.0.0/24']
           '8.0.0.4' : ['16.0.0.0/24', '15.0.0.0/24']
           '8.0.0.12': ['20.0.0.0/24']
        """
        temp_host_routes = list(host_routes)
        cidr_ip_set = netaddr.IPSet([subnet_cidr])
        host_route_dict = {}
        for route in temp_host_routes[:]:
            next_hop = route.get_next_hop()
            if netaddr.IPAddress(next_hop) in cidr_ip_set:
                if next_hop in host_route_dict:
                    host_route_dict[next_hop].append(route.get_prefix())
                else:
                    host_route_dict[next_hop] = [route.get_prefix()]
                temp_host_routes.remove(route)

        # look for indirect routes
        if temp_host_routes:
            for ipaddr in host_route_dict:
                SubnetHostRoutesHandler._port_update_prefixes(
                    host_route_dict[ipaddr], temp_host_routes)
        return host_route_dict

    @staticmethod
    def subnet_rt_fq_name(project_fq_name, subnet_id):
        rt_name = '%s_%s' % (ROUTE_TABLE_NAME_PREFIX, subnet_id)
        return project_fq_name + [rt_name]

    def _associate_vn_rt(self, vn_obj, rt_obj):
        vn_obj.add_route_table(rt_obj)
        self._vnc_lib.virtual_network_update(vn_obj)

    def get_or_create_rt(self, vn_obj, subnet_id):
        rt_fq_name = self.subnet_rt_fq_name(vn_obj.fq_name[:-1], subnet_id)
        try:
            rt_obj = self._vnc_lib.route_table_read(fq_name=rt_fq_name,
                                                    fields=['virtual_network_back_refs'])
            # check RT is correctly linked to the VN
            if not any([vn_obj.uuid == vn_ref['uuid']
                        for vn_ref in rt_obj.get_virtual_network_back_refs() or []]):
                self._associate_vn_rt(vn_obj, rt_obj)
        except vnc_exc.NoIdError:
            project_obj = self._project_read(proj_id=vn_obj.parent_uuid)
            route_table = vnc_api.RouteTable(name=rt_fq_name[-1],
                                             parent_obj=project_obj)
            rt_uuid = self._vnc_lib.route_table_create(route_table)
            rt_obj = self._vnc_lib.route_table_read(id=rt_uuid,
                                                    fields=['virtual_network_back_refs'])
            self._associate_vn_rt(vn_obj, rt_obj)
        return rt_obj

    def delete_rt(self, vn_obj, subnet_id):
        rt_fq_name = self.subnet_rt_fq_name(vn_obj.fq_name[:-1], subnet_id)
        try:
            rt_id = self._vnc_lib.fq_name_to_id('route-table', rt_fq_name)
        except vnc_exc.NoIdError:
            return
        self._vnc_lib.ref_update('virtual-network', vn_obj.uuid,
                                 'route-table', rt_id, None, 'DELETE')
        self._vnc_lib.route_table_delete(id=rt_id)

    def sync_routes(self, vn_obj, subnet_id, subnet_cidr, host_routes):
        if not host_routes:
            self.delete_rt(vn_obj, subnet_id)
            return

        host_prefixes = self.get_host_prefixes(host_routes,
                                               subnet_cidr)
        rt_obj = self.get_or_create_rt(vn_obj, subnet_id)
        routes = []
        for next_hop, prefixes in host_prefixes.items():
            for prefix in prefixes:
                routes.append(vnc_api.RouteType(prefix=prefix, next_hop=next_hop,
                                                next_hop_type="ip-address"))
        rt_obj.set_routes(vnc_api.RouteTableType.factory(routes))
        self._vnc_lib.route_table_update(rt_obj)


class SubnetHandler(SubnetGetHandler,
                    SubnetCreateHandler,
                    SubnetDeleteHandler,
                    SubnetUpdateHandler):
    pass
