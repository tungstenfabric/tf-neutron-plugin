#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import functools

from vnc_api import exceptions as vnc_exc
try:
    from neutron.common.exceptions import BadRequest
except ImportError:
    from neutron_lib.exceptions import BadRequest

try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

from neutron_lbaas.extensions import loadbalancerv2
from neutron_lbaas.extensions.loadbalancerv2 import LoadBalancerPluginBaseV2


from neutron_plugin_contrail.common import utils
from neutron_plugin_contrail.plugins.opencontrail.loadbalancer.v2 import loadbalancer_healthmonitor
from neutron_plugin_contrail.plugins.opencontrail.loadbalancer.v2 import loadbalancer_member
from neutron_plugin_contrail.plugins.opencontrail.loadbalancer.v2 import loadbalancer_pool
from neutron_plugin_contrail.plugins.opencontrail.loadbalancer.v2 import loadbalancer
from neutron_plugin_contrail.plugins.opencontrail.loadbalancer.v2 import listener

from eventlet.greenthread import getcurrent

LOG = logging.getLogger(__name__)

def set_auth_token(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        self = args[0]
        context = args[1]

        try:
            auth_token = getcurrent().contrail_vars.token
        except Exception as exc:
            raise BadRequest(resource='loadbalancer', msg=str(msg))

        if not auth_token:
            msg = "Auth-token in thread storage is set to None"
            raise BadRequest(resource='loadbalancer', msg=str(msg))

        if context.auth_token != auth_token:
            LOG.warning("Token in thread is different from context token")
            LOG.debug("Tenant ID %s" % context.tenant_id )

        # forward user token to API server for RBAC
        self.api.set_auth_token(auth_token)

        return func(*args, **kwargs)
    return wrapper


class LoadBalancerPluginDbV2(LoadBalancerPluginBaseV2):
    @property
    def api(self):
        if hasattr(self, '_api'):
            return self._api

        self._api = utils.get_vnc_api_instance()

        return self._api

    @property
    def pool_manager(self):
        if hasattr(self, '_pool_manager'):
            return self._pool_manager

        self._pool_manager = \
            loadbalancer_pool.LoadbalancerPoolManager(self.api)

        return self._pool_manager

    @property
    def loadbalancer_manager(self):
        if hasattr(self, '_loadbalancer_manager'):
            return self._loadbalancer_manager

        self._loadbalancer_manager = loadbalancer.LoadbalancerManager(self.api)

        return self._loadbalancer_manager

    @property
    def listener_manager(self):
        if hasattr(self, '_listener_manager'):
            return self._listener_manager
        self._listener_manager = listener.ListenerManager(self.api)

        return self._listener_manager

    @property
    def member_manager(self):
        if hasattr(self, '_member_manager'):
            return self._member_manager

        self._member_manager = \
            loadbalancer_member.LoadbalancerMemberManager(self.api)

        return self._member_manager

    @property
    def monitor_manager(self):
        if hasattr(self, '_monitor_manager'):
            return self._monitor_manager
        self._monitor_manager = \
            loadbalancer_healthmonitor.LoadbalancerHealthmonitorManager(
                self.api)

        return self._monitor_manager

    def get_api_client(self):
        return self.api

    @set_auth_token
    def get_loadbalancers(self, context, filters=None, fields=None):
        return self.loadbalancer_manager.get_collection(context, filters, fields)

    @set_auth_token
    def get_loadbalancer(self, context, id, fields=None):
        return self.loadbalancer_manager.get_resource(context, id, fields)

    @set_auth_token
    def create_loadbalancer(self, context, loadbalancer):
        try:
            return self.loadbalancer_manager.create(context, loadbalancer)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='loadbalancer', msg=str(ex))

    @set_auth_token
    def update_loadbalancer(self, context, id, loadbalancer):
        return self.loadbalancer_manager.update(context, id, loadbalancer)

    @set_auth_token
    def delete_loadbalancer(self, context, id):
        return self.loadbalancer_manager.delete(context, id)

    @set_auth_token
    def create_listener(self, context, listener):
        try:
            return self.listener_manager.create(context, listener)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='listener', msg=str(ex))

    @set_auth_token
    def get_listener(self, context, id, fields=None):
        return self.listener_manager.get_resource(context, id, fields)

    @set_auth_token
    def get_listeners(self, context, filters=None, fields=None):
        return self.listener_manager.get_collection(context, filters, fields)

    @set_auth_token
    def update_listener(self, context, id, listener):
        return self.listener_manager.update(context, id, listener)

    @set_auth_token
    def delete_listener(self, context, id):
        return self.listener_manager.delete(context, id)

    @set_auth_token
    def get_pools(self, context, filters=None, fields=None):
        return self.pool_manager.get_collection(context, filters, fields)

    @set_auth_token
    def get_pool(self, context, id, fields=None):
        return self.pool_manager.get_resource(context, id, fields)

    @set_auth_token
    def create_pool(self, context, pool):
        try:
            return self.pool_manager.create(context, pool)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='pool', msg=str(ex))

    @set_auth_token
    def update_pool(self, context, id, pool):
        return self.pool_manager.update(context, id, pool)

    @set_auth_token
    def delete_pool(self, context, id):
        return self.pool_manager.delete(context, id)

    @set_auth_token
    def get_pool_members(self, context, pool_id, filters=None, fields=None):
        return self.member_manager.get_collection(context, pool_id, filters, fields)

    @set_auth_token
    def get_pool_member(self, context, id, pool_id, fields=None):
        return self.member_manager.get_resource(context, id, pool_id, fields)

    @set_auth_token
    def create_pool_member(self, context, pool_id, member):
        try:
            return self.member_manager.create(context, pool_id, member)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='member', msg=str(ex))

    @set_auth_token
    def update_pool_member(self, context, id, pool_id, member):
        return self.member_manager.update(context, id, member)

    @set_auth_token
    def delete_pool_member(self, context, id, pool_id):
        return self.member_manager.delete(context, id, pool_id)

    def get_members(self, context, filters=None, fields=None):
        pass

    def get_member(self, context, id, fields=None):
        pass

    @set_auth_token
    def get_healthmonitors(self, context, filters=None, fields=None):
        return self.monitor_manager.get_collection(context, filters, fields)

    @set_auth_token
    def get_healthmonitor(self, context, id, fields=None):
        return self.monitor_manager.get_resource(context, id, fields)

    @set_auth_token
    def create_healthmonitor(self, context, healthmonitor):
        try:
            return self.monitor_manager.create(context, healthmonitor)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='healthmonitor', msg=str(ex))

    @set_auth_token
    def update_healthmonitor(self, context, id, healthmonitor):
        return self.monitor_manager.update(context, id, healthmonitor)

    @set_auth_token
    def delete_healthmonitor(self, context, id):
        return self.monitor_manager.delete(context, id)

    def stats(self, context, loadbalancer_id):
        pass

    def statuses(self, context, loadbalancer_id):
        pass

    def get_l7policies(self, context, filters=None, fields=None):
        pass

    def get_l7policy(self, context, id, fields=None):
        pass

    def create_l7policy(self, context, l7policy):
        pass

    def update_l7policy(self, context, id, l7policy):
        pass

    def delete_l7policy(self, context, id):
        pass

    def get_l7policy_rules(self, context, l7policy_id,
                           filters=None, fields=None):
        pass

    def get_l7policy_rule(self, context, id, l7policy_id, fields=None):
        pass

    def create_l7policy_rule(self, context, rule, l7policy_id):
        pass

    def update_l7policy_rule(self, context, id, rule, l7policy_id):
        pass

    def delete_l7policy_rule(self, context, id, l7policy_id):
        pass

    def create_graph(self, context, graph):
        pass
