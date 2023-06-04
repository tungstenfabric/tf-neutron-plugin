# Copyright 2014 Juniper Networks.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, unicode_literals

import datetime
import uuid
import mock
import unittest

from neutron_plugin_contrail.common import utils

try:
    from oslo_config import cfg
except ImportError:
    from oslo.config import cfg

from neutron.api import extensions
from neutron.tests.unit import _test_extension_portbindings as test_bindings

try:
    from neutron.tests.unit import test_db_plugin as test_plugin
except ImportError:
    from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin

try:
    from neutron.tests.unit import test_extension_security_group as test_sg
except ImportError:
    from neutron.tests.unit.extensions import test_securitygroup as test_sg

try:
    from neutron.tests.unit import test_extensions
except ImportError:
    from neutron.tests.unit.api import test_extensions

try:
    from neutron.tests.unit import test_l3_plugin
except ImportError:
    from neutron.tests.unit.extensions import test_l3 as test_l3_plugin

from neutron_plugin_contrail.plugins.opencontrail.vnc_client.contrail_res_handler import ContrailResourceHandler
from neutron_plugin_contrail.tests.unit.opencontrail.vnc_mock import MockVnc
from vnc_api import vnc_api
from neutron_plugin_contrail.plugins.opencontrail import contrail_plugin_base as plugin_base
from neutron_plugin_contrail.plugins.opencontrail.contrail_plugin import NeutronPluginContrailCoreV2
from neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_v3 import NeutronPluginContrailCoreV3

CONTRAIL_PKG_PATH = "neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_v3"


class Context(object):
    def __init__(self, tenant_id=''):
        self.read_only = False
        self.show_deleted = False
        self.roles = [u'admin', u'KeystoneServiceAdmin', u'KeystoneAdmin']
        self._read_deleted = 'no'
        self.timestamp = datetime.datetime.now()
        self.auth_token = None
        self._session = None
        self._is_admin = True
        self.admin = uuid.uuid4().hex
        self.request_id = 'req-' + str(uuid.uuid4())
        self.tenant = tenant_id


class KeyStoneInfo(object):
    """To generate Keystone Authentication information.

       Contrail Driver expects Keystone auth info for testing purpose.
    """
    auth_protocol = 'http'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    auth_url = "http://localhost:5000/"
    auth_type = ""
    admin_password = 'neutron'
    admin_token = 'neutron'
    admin_tenant_name = 'neutron'
    insecure = True
    certfile = "fake_cert.pem"
    keyfile = "fake_key.pem"
    cafile = "fake_ca.pem"
    auth_uri = "/v3"
    auth_version = "v3"


class JVContrailPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = '%s.NeutronPluginContrailCoreV3' % CONTRAIL_PKG_PATH

    def setUp(self, plugin=None, ext_mgr=None):
        cfg.CONF.keystone_authtoken = KeyStoneInfo()
        from neutron_plugin_contrail import extensions
        cfg.CONF.api_extensions_path = "extensions:" + extensions.__path__[0]
        res_handler = ContrailResourceHandler

        # mimic the project id format change
        @staticmethod
        def mock_proj_id_vnc_to_neutron(y):
            if y is not None:
                return y.lower()
            return y

        @staticmethod
        def mock_proj_id_neutron_to_vnc(y):
            if y is not None:
                return y.upper()
            return y

        res_handler._project_id_vnc_to_neutron = mock_proj_id_vnc_to_neutron
        res_handler._project_id_neutron_to_vnc = mock_proj_id_neutron_to_vnc

        utils.get_vnc_api_instance = lambda *args, **kwargs: MockVnc()
        self.domain_obj = vnc_api.Domain()
        MockVnc().domain_create(self.domain_obj)

        self._neutron_set_user_auth_token = NeutronPluginContrailCoreV3._set_user_auth_token
        NeutronPluginContrailCoreV3._set_user_auth_token = lambda *args, **kwargs: None

        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        MockVnc.resources_collection = dict()
        MockVnc._kv_dict = dict()
        NeutronPluginContrailCoreV3._set_user_auth_token = self._neutron_set_user_auth_token
        super(JVContrailPluginTestCase, self).tearDown()


class TestContrailNetworksV2(test_plugin.TestNetworksV2,
                             JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailNetworksV2, self).setUp()

    def test_create_network_default_mtu(self):
        self.skipTest("Contrail doesn't support this feature yet")

    def test_create_network_vlan_transparent(self):
        self.skipTest("Contrail doesn't support this feature yet")

    def test_update_network_set_not_shared_multi_tenants2_returns_409(self):
        self.skipTest("Not supported test case")

    def test_update_network_set_not_shared_multi_tenants_returns_409(self):
        self.skipTest("Not supported test case")

    def test_update_network_set_not_shared_other_tenant_access_via_rbac(self):
        self.skipTest("(sqlite3.IntegrityError) foreign key constraint failed")

    def test_update_network_set_not_shared_other_tenant_returns_409(self):
        self.skipTest("Not supported test case")

    def test_update_network_set_not_shared_single_tenant(self):
        self.skipTest("Not supported test case")

    def test_update_network_with_subnet_set_shared(self):
        self.skipTest("TODO: neutron_lib.exceptions.SubnetNotFound")

    def test_list_shared_networks_with_non_admin_user(self):
        self.skipTest("Not supported test case")


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2,
                            JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailSubnetsV2, self).setUp()

    def test_create_2_subnets_overlapping_cidr_not_allowed_returns_400(self):
        self.skipTest("TODO: Not supported yet")

    def test_create_subnet_bad_tenant(self):
        self.skipTest("TODO: Investigate, why this fails in neutron itself")

    def test_create_subnet_ipv6_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_create_subnet_ipv6_same_ra_and_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_delete_subnet_port_exists_owned_by_other(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_port_prevents_subnet_deletion(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_delete_subnet_ipv6_slaac_router_port_exists(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_delete_subnet_ipv6_slaac_port_exists(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_create_subnet_ipv6_different_ra_and_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_create_subnet_ipv6_ra_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_update_subnet(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_no_gateway(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_route_with_too_many_entries(self):
        self.skipTest("TODO: Investigate - support multiple host routes")

    def test_update_subnet_gw_ip_in_use_returns_409(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        self.skipTest("Contrail does not support updating allocation pools")

    def test_update_subnet_allocation_pools(self):
        self.skipTest("Contrail does not support updating allocation pools")

    def test_update_subnet_dns_with_too_many_entries(self):
        self.skipTest("TODO: Check why this should fail")

    # Support ipv6 in contrail is planned in Juno
    def test_create_subnet_ipv6_ra_mode_ip_version_4(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_with_v6_allocation_pool(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_gw_values(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_cannot_disable_dhcp(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_attributes_no_dhcp_enabled(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_attributes(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_address_attribute(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_enable_dhcp(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_ra_attribute(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_delete_subnet_dhcp_port_associated_with_other_subnets(self):
        self.skipTest("There is no dhcp port in contrail")

    def test_validate_subnet_host_routes_exhausted(self):
        self.skipTest("TODO : Need to revisit")

    def test_validate_subnet_dns_nameservers_exhausted(self):
        self.skipTest("TODO : Need to revisit")

    def test_create_subnet(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_defaults(self):
        self.skipTest("Not supported test case")

    def test_delete_subnet(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_dhcpv6_stateless_with_port_on_network(self):
        self.skipTest("Not supported test case")

    def test_delete_subnet_port_exists_owned_by_network(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_gw_outside_cidr_returns_201(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_gw_values(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_invalid_gw_V4_cidr(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_ipv6_first_ip_owned_by_non_router(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_ipv6_gw_is_nw_end_addr(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_ipv6_gw_is_nw_start_addr(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_ipv6_gw_is_nw_start_addr_canonicalize(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_ipv6_out_of_cidr_global(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_ipv6_pd_gw_values(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_ipv6_slaac_with_dhcp_port_on_network(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_ipv6_slaac_with_port_not_found(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_multiple_allocation_pools(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_no_cidr_and_default_subnetpool(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_nonzero_cidr(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_allocation_pool(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_cidr_and_default_subnetpool(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_dhcp_disabled(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_invalid_netmask_returns_400_ipv4(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_invalid_netmask_returns_400_ipv6(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_large_allocation_pool(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_network_different_tenant(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_none_gateway(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_none_gateway_allocation_pool(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_none_gateway_fully_allocated(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_one_dns(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_one_host_route(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_two_dns(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_two_host_routes(self):
        self.skipTest("Not supported test case")

    def test_create_subnet_with_v6_pd_allocation_pool(self):
        self.skipTest("Not supported test case")

    def test_bulk_create_subnet_ipv6_auto_addr_with_port_on_network(self):
        self.skipTest("TODO: MismatchError: 3 != 1")

    def test_create_subnet_ipv6_slaac_with_port_on_network(self):
        self.skipTest("Not supported test case")

    def test_delete_subnet_with_callback(self):
        self.skipTest("TODO: MismatchError: 'SubnetInUse' != 'SubnetNotFound'")

    def test_delete_subnet_with_dns(self):
        self.skipTest("Not supported test case")

    def test_delete_subnet_with_dns_and_route(self):
        self.skipTest("Not supported test case")

    def test_delete_subnet_with_other_subnet_on_network_still_in_use(self):
        self.skipTest("Not supported test case")

    def test_delete_subnet_with_route(self):
        self.skipTest("Not supported test case")

    def test_get_subnets_count_filter_by_project_id(self):
        self.skipTest("TODO: MismatchError: 1 != 3")

    def test_subnet_lifecycle_dns_retains_order(self):
        self.skipTest("Not supported test case")

    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        self.skipTest("Not supported test case")

    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_allocation_pools_and_gateway_ip(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_allocation_pools_invalid_pool_for_cidr(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_allocation_pools_invalid_returns_400(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_allocation_pools_over_gateway_ip_returns_409(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_allocation_pools_overlapping_returns_409(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_from_gw_to_new_gw(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_from_gw_to_no_gw(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_from_no_gw_to_no_gw(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_gw_ip_in_use_by_router_returns_409(self):
        self.skipTest("TODO: sqlite3.IntegrityError foreign key "
                      "constraint failed")

    def test_update_subnet_gw_outside_cidr_returns_200(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_inconsistent_ipv4_dns_v6(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_inconsistent_ipv4_gatewayv6(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        self.skipTest("Not supported test case")

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        self.skipTest("Not supported test case")

    def test_create_two_subnets(self):
        self.skipTest("Not supported test case")

    def test_show_subnet(self):
        self.skipTest("TODO: KeyError 'subnet' in response")

    def test_subnet_usable_after_update(self):
        self.skipTest("TODO: KeyError 'subnet' in response")

    def test_update_subnet_adding_additional_host_routes_and_dns(self):
        self.skipTest("TODO: KeyError 'subnet' in response")

    def test_update_subnet_dns(self):
        self.skipTest("TODO: KeyError 'subnet' in response")

    def test_update_subnet_dns_to_None(self):
        self.skipTest("TODO: KeyError 'subnet' in response")

    def test_update_subnet_route(self):
        self.skipTest("TODO: KeyError 'subnet' in response")

    def test_update_subnet_route_to_None(self):
        self.skipTest("TODO: KeyError 'subnet' in response")

    def test_list_subnets_filtering_by_project_id(self):
        self.skipTest("TODO: First sequence contains 2 additional elements")


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailPortsV2, self).setUp()
        self.port_create_status = 'DOWN'

    def test_requested_split(self):
        self.skipTest("TODO: Mocking complexity")

    def test_requested_invalid_fixed_ips(self):
        self.skipTest("TODO: Complete this functionality")

    def test_ip_allocation_for_ipv6_subnet_slaac_address_mode(self):
        self.skipTest("Not Supported yet")

    def test_requested_duplicate_mac(self):
        self.skipTest("TODO: Failure because of base_mac setting")

    def test_mac_exhaustion(self):
        self.skipTest("Specific to neutron")

    def test_mac_generation(self):
        self.skipTest("TODO: Failure because of base_mac setting")

    def test_mac_generation_4octet(self):
        self.skipTest("TODO: Failure because of base_mac setting")

    def test_bad_mac_format(self):
        self.skipTest("TODO: Failure because of base_mac setting")

    def test_update_port_not_admin(self):
        self.skipTest("TODO: Understand what this test cases is all about")

    def test_update_port_mac_bad_owner(self):
        self.skipTest("TODO: Understand what this test case is all about")

    def test_create_port_bad_tenant(self):
        self.skipTest("TODO: Investigate, why this fails in neutron itself")

    def test_requested_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest("TODO: Investigate why this fails in neutron itself")

    def test_requested_subnet_id_v4_and_v6_slaac(self):
        self.skipTest("TODO: Investigate why this fails in neutron itself")

    def test_requested_subnet_id_v6_slaac(self):
        self.skipTest("TODO: Investigate why this fails in neutron itself")

    def test_update_port_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest("TODO: Investigate")

    def test_update_port_with_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest('Not Supported yet')

    def test_ip_allocation_for_ipv6_2_subnet_slaac_mode(self):
        self.skipTest("Not Supported yet")

    def test_create_port_with_multiple_ipv4_and_ipv6_subnets(self):
        self.skipTest("Not Supported yet")

    def test_create_port_with_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest("Not Supported yet")

    def test_update_port_mac_v6_slaac(self):
        self.skipTest("Not Supported yet")

    def test_update_port_excluding_ipv6_slaac_subnet_from_fixed_ips(self):
        self.skipTest('Not Supported yet')

    def test_delete_ports_by_device_id(self):
        self.skipTest("This method tests rpc API of "
                      "which contrail isn't using")

    def test_delete_ports_by_device_id_second_call_failure(self):
        self.skipTest("This method tests rpc API of "
                      "which contrail isn't using")

    def test_delete_ports_ignores_port_not_found(self):
        self.skipTest("This method tests private method of "
                      "which contrail isn't using")

    def test_create_port_invalid_fixed_ip_address_v6_pd_slaac(self):
        self.skipTest("Not supported test case")

    def test_create_port_public_network(self):
        self.skipTest("Not supported test case")

    def test_create_port_public_network_with_invalid_ip_and_subnet_id(self):
        self.skipTest("Not supported test case")

    def test_create_port_public_network_with_invalid_ip_no_subnet_id(self):
        self.skipTest("Not supported test case")

    def test_create_port_public_network_with_ip(self):
        self.skipTest("Not supported test case")

    def test_create_port_with_ipv6_pd_subnet_in_fixed_ips(self):
        self.skipTest("Not supported test case")

    def test_create_ports_bulk_emulated_plugin_failure(self):
        self.skipTest("Not supported test case")

    def test_create_router_port_ipv4_and_ipv6_slaac_no_fixed_ips(self):
        self.skipTest("Not supported test case")

    def test_delete_network_port_exists_owned_by_network(self):
        self.skipTest("Not supported test case")

    def test_delete_network_port_exists_owned_by_network_port_not_found(self):
        self.skipTest("Not supported test case")

    def test_delete_network_port_exists_owned_by_network_race(self):
        self.skipTest("Not supported test case")

    def test_duplicate_mac_generation(self):
        self.skipTest("Not supported test case")

    def test_is_mac_in_use(self):
        self.skipTest("Not supported test case")

    def test_list_ports_public_network(self):
        self.skipTest("Not supported test case")

    def test_no_more_port_exception(self):
        self.skipTest("Not supported test case")

    def test_requested_ips_only(self):
        self.skipTest("TODO: MismatchError: 1 != 2")

    def test_update_port_invalid_fixed_ip_address_v6_pd_slaac(self):
        self.skipTest("Not supported test case")

    def test_update_port_invalid_subnet_v6_pd_slaac(self):
        self.skipTest("Not supported test case")

    def test_update_port_mac(self):
        self.skipTest("Not supported test case")

    def test_delete_port_public_network(self):
        self.skipTest("Not supported test case")

    def test_update_port_with_stale_subnet(self):
        self.skipTest("Not supported test case")

    def test_update_port_with_new_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest("TODO: MismatchError: 1 != 2")

    def test_test_delete_network_port_exists_dhcp(self):
        self.skipTest("TODO: MismatchError: 204 != 409")

    def test_test_delete_network_port_exists_fip_gw(self):
        self.skipTest("TODO: MismatchError: 204 != 409")


class TestContrailSecurityGroups(test_sg.TestSecurityGroups,
                                 JVContrailPluginTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        super(TestContrailSecurityGroups, self).setUp(self._plugin_name,
                                                      ext_mgr)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_create_security_group_rule_duplicate_rule_in_post_emulated(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_duplicate_rule_db_emulated(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_duplicate_rules(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_invalid_ethertype_for_prefix(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_invalid_ip_prefix(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_source_group_ip_and_ip_prefix(self):
        self.skipTest("Investigation needed")

    def test_create_delete_security_group_port_in_use(self):
        self.skipTest("Investigation needed")

    def test_create_security_group(self):
        self.skipTest("TODO: MismatchError: None != u'0.0.0.0/0'")

    def test_create_security_group_rule_duplicate_rules_diff_desc(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_duplicate_rules_proto_name_num(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_duplicate_rules_proto_num_name(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_icmp_with_code_only(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_icmpv6_legacy_protocol_name(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_icmpv6_with_type_only(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_protocol_as_number_port_bad(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rules_admin_tenant(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rules_native_quotas(self):
        self.skipTest("Not supported test case")

    def test_create_security_groups_native_quotas(self):
        self.skipTest("Not supported test case")

    def test_get_security_group_empty_rules(self):
        self.skipTest("TODO: MismatchError: 0 != 1")

    def test_list_security_group_rules(self):
        self.skipTest("TODO: First sequence contains 1 additional element")

    def test_list_security_group_rules_with_pagination(self):
        self.skipTest("TODO: MismatchError: 2 != 3")

    def test_list_security_group_rules_with_pagination_reverse(self):
        self.skipTest("TODO: MismatchError: 2 != 3")

    def test_list_security_group_rules_with_sort(self):
        self.skipTest("TODO: MismatchError (lists of uuids not the same)")

    def test_list_security_groups(self):
        self.skipTest("Not supported test case")

    def test_security_group_list_creates_default_security_group(self):
        self.skipTest("Not supported test case")

    def test_security_group_port_create_creates_default_security_group(self):
        self.skipTest("Not supported test case")

    def test_delete_default_security_group_nonadmin(self):
        self.skipTest("Not supported test case")

    def test_update_default_security_group_name_fail(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_ipv6_icmp_legacy_protocol_name(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_ipv6_icmp_legacy_protocol_num(self):
        self.skipTest("Not supported test case")

    def test_default_security_group_rules(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_icmp_with_type_only(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_port_range_min_only(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_protocol_as_number_with_port_bad(self):
        self.skipTest("Not supported test case")

    def test_create_security_group_rule_port_range_min_max_limits(self):
        self.skipTest("TODO: MismatchError: None != 1")


class TestContrailPortBinding(JVContrailPluginTestCase,
                              test_bindings.PortBindingsTestCase):
    # from neutron_plugin_contrail.plugins.opencontrail.contrail_plugin
    # import (NeutronPluginContrailCoreV2)
    VIF_TYPE = plugin_base.VIF_TYPE_VROUTER
    HAS_PORT_FILTER = True

    def setUp(self):
        super(TestContrailPortBinding, self).setUp()

    def test_port_create_portinfo_non_admin(self):
        self.skipTest("Not supported test case")

    def test_ports_vif_details(self):
        self.skipTest("TODO: 'NoneType' object has no attribute 'get'")


class TestContrailL3NatTestCase(JVContrailPluginTestCase,
                                test_l3_plugin.L3NatDBIntTestCase):
    mock_rescheduling = False

    def setUp(self):
        super(TestContrailL3NatTestCase, self).setUp()

    def test_router_update_gateway_with_existed_floatingip(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_update_gateway_to_empty_with_existed_floatingip(self):
        self.skipTest("Feature needs to be implemented")

    def test_two_fips_one_port_invalid_return_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_gateway_dup_subnet1_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_interface_dup_subnet2_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_interface_overlapped_cidr_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_with_invalid_create_port(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_list_with_pagination_reverse(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_floatingip_no_ext_gateway_return_404(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_router_port_with_device_id_of_other_teants_router(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_delete_subnet_inuse_returns_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_network_update_external_failure(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_interface_ipv6_subnet_without_gateway_ip(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_gateway_no_subnet_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_list_with_pagination(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_gateway_dup_subnet2_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_with_assoc_fails(self):
        self.skipTest("Feature needs to be implemented")

    def test_floating_ip_direct_port_delete_returns_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_multi_external_one_internal(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_create_call_extensions(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_interface_subnet_with_port_from_other_tenant(self):
        self.skipTest("TODO : Need to revisit")

    def test_router_add_interface_subnet(self):
        self.skipTest("TODO : Need to revisit")

    def test_router_add_interface_dup_subnet1_returns_400(self):
        self.skipTest("TODO : Need to revisit")

    def test_floatingip_list_with_sort(self):
        self.skipTest("TODO : Need to revisit")

    def test_create_non_router_port_device_id_of_other_teants_router_update(
            self):
        self.skipTest("Not supported test case")

    def test__notify_subnetpool_address_scope_update(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_no_public_subnet_returns_400(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_assoc(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_assoc_to_ipv4_and_ipv6_port(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_duplicated_specific_ip(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_specific_ip(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_specific_ip_out_of_allocation(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_subnet_and_invalid_fip_address(self):
        self.skipTest(
            "TODO: MismatchError: 'InvalidIpForSubnet' != 'BadRequest'")

    def test_create_floatingip_with_subnet_id_and_fip_address(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_subnet_id_non_admin(self):
        self.skipTest("Not supported test case")

    def test_create_floatingips_native_quotas(self):
        self.skipTest("Not supported test case")

    def test_create_multiple_floatingips_same_fixed_ip_same_port(self):
        self.skipTest("Not supported test case")

    def test_create_router_port_with_device_id_of_other_tenants_router(self):
        self.skipTest("Not supported test case")

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        self.skipTest("Not supported test case")

    def test_first_floatingip_associate_notification(self):
        self.skipTest("Not supported test case")

    def test_floating_port_status_not_applicable(self):
        self.skipTest("Not supported test case")

    def test_floatingip_association_on_unowned_router(self):
        self.skipTest("Not supported test case")

    def test_floatingip_crd_ops(self):
        self.skipTest("Not supported test case")

    def test_floatingip_create_different_fixed_ip_same_port(self):
        self.skipTest("Not supported test case")

    def test_floatingip_disassociate_notification(self):
        self.skipTest("Not supported test case")

    def test_floatingip_list_with_port_id(self):
        self.skipTest("Not supported test case")

    def test_floatingip_port_delete(self):
        self.skipTest("Not supported test case")

    def test_floatingip_same_external_and_internal(self):
        self.skipTest("Not supported test case")

    def test_floatingip_update(self):
        self.skipTest("Not supported test case")

    def test_floatingip_update_different_fixed_ip_same_port(self):
        self.skipTest("Not supported test case")

    def test_floatingip_update_different_port_owner_as_admin(self):
        self.skipTest("Not supported test case")

    def test_floatingip_update_different_router(self):
        self.skipTest("Not supported test case")

    def test_floatingip_update_invalid_fixed_ip(self):
        self.skipTest("Not supported test case")

    def test_floatingip_update_same_fixed_ip_same_port(self):
        self.skipTest("Not supported test case")

    def test_floatingip_update_subnet_gateway_disabled(self):
        self.skipTest("Not supported test case")

    def test_floatingip_update_to_same_port_id_twice(self):
        self.skipTest("Not supported test case")

    def test_floatingip_via_router_interface_returns_201(self):
        self.skipTest("TODO: NeutronPluginContrailCoreV3 does not have "
                      "the attribute 'get_router_for_floatingip'")

    def test_janitor_clears_orphaned_floatingip_port(self):
        self.skipTest("TODO: NeutronPluginContrailCoreV3 does not have "
                      "the attribute '_clean_garbage'")

    def test_janitor_doesnt_delete_if_fixed_in_interim(self):
        self.skipTest("TODO: NeutronPluginContrailCoreV3 does not have "
                      "the attribute '_clean_garbage'")

    def test_floatingip_via_router_interface_returns_404(self):
        self.skipTest("Not supported test case")

    def test_janitor_updates_port_device_id(self):
        self.skipTest("Not supported test case")

    def test_router_add_gateway_no_subnet_forbidden(self):
        self.skipTest("Not supported test case")

    def test_router_add_iface_ipv6_ext_ra_subnet_returns_400(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_by_port_admin_address_out_of_pool(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_by_port_cidr_overlapped_with_gateway(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_by_port_other_tenant_address_in_pool(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_by_subnet_other_tenant_subnet_returns_400(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_cidr_overlapped_with_gateway(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_delete_port_after_failure(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_dup_port(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_ipv6_subnet(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_multiple_ipv4_subnet_port_returns_400(self):
        self.skipTest("TODO: AssertionError: Calls not found")

    def test_router_add_interface_multiple_ipv4_subnets(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_multiple_ipv6_subnet_port(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_multiple_ipv6_subnets_different_net(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_port(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_port_bad_tenant_returns_404(self):
        self.skipTest("Not supported test case")

    def test_router_add_interface_subnet_with_bad_tenant_returns_404(self):
        self.skipTest("Not supported test case")

    def test_router_clear_gateway_callback_failure_returns_409(self):
        self.skipTest("Not supported test case")

    def test_router_delete_callback(self):
        self.skipTest("Not supported test case")

    def test_router_delete_dhcpv6_stateless_subnet_inuse_returns_409(self):
        self.skipTest("Not supported test case")

    def test_router_delete_ipv6_slaac_subnet_inuse_returns_409(self):
        self.skipTest("Not supported test case")

    def test_router_delete_race_with_interface_add(self):
        self.skipTest("Not supported test case")

    def test_router_delete_with_floatingip_existed_returns_409(self):
        self.skipTest("Not supported test case")

    def test_router_delete_with_port_existed_returns_409(self):
        self.skipTest("Not supported test case")

    def test_router_remove_interface_callback_failure_returns_409(self):
        self.skipTest("Not supported test case")

    def test_router_remove_interface_inuse_returns_409(self):
        self.skipTest("Not supported test case")

    def test_router_remove_interface_nothing_returns_400(self):
        self.skipTest("Not supported test case")

    def test_router_remove_interface_returns_200(self):
        self.skipTest("Not supported test case")

    def test_router_remove_interface_with_both_ids_returns_200(self):
        self.skipTest("Not supported test case")

    def test_router_remove_interface_wrong_port_returns_404(self):
        self.skipTest("Not supported test case")

    def test_router_remove_interface_wrong_subnet_returns_400(self):
        self.skipTest("Not supported test case")

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest("Not supported test case")

    def test_router_specify_id_backend(self):
        self.skipTest("TODO: MismatchError, uuids are not equal")

    def test_router_update_gateway_with_external_ip_used_by_gw(self):
        self.skipTest("Not supported test case")

    def test_router_update_gateway_with_invalid_external_ip(self):
        self.skipTest("Not supported test case")

    def test_router_update_gateway_with_invalid_external_subnet(self):
        self.skipTest("Not supported test case")

    def test_update_port_device_id_to_different_tenants_router(self):
        self.skipTest("Not supported test case")

    def test_update_router_interface_port_ip_not_allowed(self):
        self.skipTest("Not supported test case")

    def test_update_router_interface_port_ipv6_subnet_ext_ra(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_ipv6_only_network_returns_400(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_assoc_to_ipv6_subnet(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_specific_ip_out_of_subnet(self):
        self.skipTest("Not supported test case")

    def test_create_floatingip_with_wrong_subnet_id(self):
        self.skipTest("Not supported test case")

    def test_create_router_gateway_fails(self):
        self.skipTest("Not supported test case")

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")

    def test_create_floatingip_with_multisubnet_id(self):
        self.skipTest("TODO: 'floating IP doesn't have "
                      "'floating_ip_address'")

    def test_create_non_router_port_device_id_of_other_tenants_router_update(self):
        self.skipTest("Not supported test case")

    def test_rtest_router_add_gateway_notificationsouter_add_gateway_notifications(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")

    def test_router_create_with_gwinfo_ext_ip(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")

    def test_router_create_with_gwinfo_ext_ip_subnet(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")

    def test_router_update_gateway_add_multiple_prefixes_ipv6(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")

    def test_router_update_gateway_upon_subnet_create_ipv6(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")

    def test_router_update_gateway_with_different_external_subnet(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")

    def test_router_add_gateway_notifications(self):
        self.skipTest("TODO: method '_get_external_gateway_info' "
                      "in 'router_res_handler.py doesn't "
                      "return 'external_fixed_ips' field")


class ContrailPluginV2Test(unittest.TestCase):
    def setUp(self):
        cfg.CONF.keystone_authtoken = KeyStoneInfo()
        self.plugin = NeutronPluginContrailCoreV2()

    def test_exception_raised_on_resource_creation_failure(self):
        """ Exception should be raised when API server returns OverQuota error """

        resource_type = "network"
        context = Context(tenant_id='e17301da-7a64-4210-c77e-9fb9738674a9')
        res_data = {'network': {'name': 'fake_network',
                                'admin_state_up': True,
                                'tenant_id': context.tenant}}
        status_code = 400
        response_info = {u'msg': u'quota limit (3) exceeded for resource virtual_network',
                         u'exception': u'OverQuota',
                         u'overs': [u'virtual_network']}

        over_quota_error = (status_code, response_info)

        with mock.patch.object(NeutronPluginContrailCoreV2,
                               '_request_backend',
                               return_value=over_quota_error), self.assertRaises(Exception):
            self.plugin._create_resource(resource_type, context, res_data)
