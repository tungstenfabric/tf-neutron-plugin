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

from vnc_api import exceptions as vnc_exc
from vnc_api import vnc_api

from neutron_plugin_contrail.common.utils import get_tenant_id
from neutron_plugin_contrail.plugins.opencontrail.vnc_client.contrail_res_handler import (
    ResourceCreateHandler,
    ResourceDeleteHandler,
    ResourceGetHandler,
    ResourceUpdateHandler,
    SGHandler,
)


class SecurityGroupMixin(object):
    def _security_group_vnc_to_neutron(self, sg_obj,
                                       contrail_extensions_enabled=False,
                                       fields=None):
        from neutron_plugin_contrail.plugins.opencontrail.vnc_client.sgrule_res_handler import SecurityGroupRuleHandler

        sg_q_dict = {}
        extra_dict = {}
        extra_dict['fq_name'] = sg_obj.get_fq_name()

        # replace field names
        sg_q_dict['id'] = sg_obj.uuid
        sg_q_dict['tenant_id'] = self._project_id_vnc_to_neutron(
            sg_obj.parent_uuid)
        sg_q_dict['project_id'] = sg_q_dict['tenant_id']
        if not sg_obj.display_name:
            # for security groups created directly via vnc_api
            sg_q_dict['name'] = sg_obj.get_fq_name()[-1]
        else:
            sg_q_dict['name'] = sg_obj.display_name
        sg_q_dict['description'] = sg_obj.get_id_perms().get_description()

        # get security group rules
        sg_q_dict['security_group_rules'] = []
        rule_list = SecurityGroupRuleHandler(
            self._vnc_lib).security_group_rules_read(sg_obj)

        if rule_list:
            for rule in rule_list:
                sg_q_dict['security_group_rules'].append(rule)

        if contrail_extensions_enabled:
            sg_q_dict.update(extra_dict)

        if fields:
            sg_q_dict = self._filter_res_dict(sg_q_dict, fields)
        return sg_q_dict
    # end _security_group_vnc_to_neutron

    def _security_group_neutron_to_vnc(self, sg_q, sg_vnc):
        if 'name' in sg_q and sg_q['name']:
            sg_vnc.display_name = sg_q['name']
        if 'description' in sg_q:
            id_perms = sg_vnc.get_id_perms()
            id_perms.set_description(sg_q['description'])
            sg_vnc.set_id_perms(id_perms)
        return sg_vnc
    # end _security_group_neutron_to_vnc

    def _create_default_security_group(self, proj_obj):
        def _get_rule(ingress, sg, prefix, ethertype):
            sgr_uuid = str(uuid.uuid4())
            if sg:
                addr = vnc_api.AddressType(
                    security_group=proj_obj.get_fq_name_str() + ':' + sg)
            elif prefix:
                addr = vnc_api.AddressType(
                    subnet=vnc_api.SubnetType(prefix, 0))
            local_addr = vnc_api.AddressType(security_group='local')
            if ingress:
                src_addr = addr
                dst_addr = local_addr
            else:
                src_addr = local_addr
                dst_addr = addr
            rule = vnc_api.PolicyRuleType(
                rule_uuid=sgr_uuid, direction='>', protocol='any',
                src_addresses=[src_addr],
                src_ports=[vnc_api.PortType(0, 65535)],
                dst_addresses=[dst_addr],
                dst_ports=[vnc_api.PortType(0, 65535)],
                ethertype=ethertype)
            return rule

        rules = [_get_rule(True, 'default', None, 'IPv4'),
                 _get_rule(True, 'default', None, 'IPv6'),
                 _get_rule(False, None, '0.0.0.0', 'IPv4'),
                 _get_rule(False, None, '::', 'IPv6')]
        sg_rules = vnc_api.PolicyEntriesType(rules)

        # create security group
        id_perms = vnc_api.IdPermsType(enable=True,
                                       description='Default security group')
        sg_obj = vnc_api.SecurityGroup(
            name='default', parent_obj=proj_obj,
            id_perms=id_perms,
            security_group_entries=sg_rules)

        self._vnc_lib.security_group_create(sg_obj)
        return sg_obj.uuid

    def _ensure_default_security_group_exists(self, proj_id):
        if proj_id is None:
            projects = self._vnc_lib.projects_list()['projects']
            for project in projects:
                self._ensure_default_security_group_exists(project['uuid'])

            return

        proj_id = self._project_id_neutron_to_vnc(proj_id)
        proj_obj = self._vnc_lib.project_read(id=proj_id,
                                              fields=['security_groups'])
        sg_groups = proj_obj.get_security_groups()
        for sg_group in sg_groups or []:
            if sg_group['to'][-1] == 'default':
                return sg_group['uuid']
        return self._create_default_security_group(proj_obj)
    # end _ensure_default_security_group_exists


class SecurityGroupBaseGet(ResourceGetHandler):
    resource_get_method = "security_group_read"


class SecurityGroupGetHandler(SecurityGroupBaseGet, SecurityGroupMixin):
    resource_list_method = "security_groups_list"

    def get_sg_obj(self, id=None, fq_name_str=None):
        return self._resource_get(id=id, fq_name_str=fq_name_str)

    def resource_get(self, context, sg_id, fields=None):
        contrail_extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)
        try:
            sg_obj = self._resource_get(id=sg_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception(
                'SecurityGroupNotFound', id=sg_id, resource='security_group')

        return self._security_group_vnc_to_neutron(
            sg_obj, contrail_extensions_enabled, fields=fields)

    def resource_list_by_project(self, project_id, filters=None):
        if project_id:
            try:
                project_uuid = self._project_id_neutron_to_vnc(project_id)
                # Trigger a project read to ensure project sync
                self._project_read(proj_id=project_uuid)
            except vnc_exc.NoIdError:
                return []
        else:
            project_uuid = None

        obj_uuids = None
        if filters and 'id' in filters:
            obj_uuids = filters['id']

        sg_objs = self._resource_list(parent_id=project_uuid,
                                      detail=True, obj_uuids=obj_uuids)
        return sg_objs

    def resource_list(self, context, filters=None, fields=None):
        ret_list = []

        contrail_extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)
        # collect phase
        project_id = context.get('tenant')
        self._ensure_default_security_group_exists(project_id)

        all_sgs = []  # all sgs in all projects
        if context and not context['is_admin']:
            project_sgs = self.resource_list_by_project(
                self._project_id_neutron_to_vnc(get_tenant_id(context)),
                filters=filters)
            all_sgs.append(project_sgs)
        else:  # admin context
            if filters and 'tenant_id' in filters:
                project_ids = self._validate_project_ids(
                    context, filters['tenant_id'])
                for p_id in project_ids:
                    project_sgs = self.resource_list_by_project(p_id,
                                                                filters=filters)
                    all_sgs.append(project_sgs)
            else:  # no tenant id filter
                all_sgs.append(self.resource_list_by_project(None,
                                                             filters=filters))

        # prune phase
        no_rule = SGHandler(
            self._vnc_lib).get_no_rule_security_group(create=False)
        for project_sgs in all_sgs:
            for sg_obj in project_sgs:
                if no_rule and sg_obj.uuid == no_rule.uuid:
                    continue
                if not self._filters_is_present(
                        filters, 'name',
                        sg_obj.get_display_name() or sg_obj.name):
                    continue
                if not self._filters_is_present(
                        filters, 'description',
                        sg_obj.get_id_perms().get_description()):
                    continue
                sg_info = self._security_group_vnc_to_neutron(
                    sg_obj, contrail_extensions_enabled, fields=fields)
                ret_list.append(sg_info)

        return ret_list


class SecurityGroupDeleteHandler(SecurityGroupBaseGet, ResourceDeleteHandler):
    resource_delete_method = "security_group_delete"

    def resource_delete(self, context, sg_id):
        try:
            sg_obj = self._resource_get(id=sg_id)
            if sg_obj.name == 'default' and (
               self._project_id_neutron_to_vnc(context.get('tenant')) ==
               sg_obj.parent_uuid):
                # Deny delete if the security group name is default and
                # the owner of the SG is deleting it.
                self._raise_contrail_exception(
                    'SecurityGroupCannotRemoveDefault')
        except vnc_exc.NoIdError:
            return

        try:
            self._resource_delete(sg_id)
        except vnc_exc.RefsExistError:
            self._raise_contrail_exception(
                'SecurityGroupInUse', id=sg_id, resource='security_group')


class SecurityGroupUpdateHandler(ResourceUpdateHandler,
                                 SecurityGroupBaseGet,
                                 SecurityGroupMixin):
    resource_update_method = "security_group_update"

    def resource_update_obj(self, sg_obj):
        self._resource_update(sg_obj)

    def resource_update(self, context, sg_id, sg_q):
        sg_q['id'] = sg_id
        contrail_extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)
        try:
            sg_obj = self._security_group_neutron_to_vnc(
                sg_q,
                self._resource_get(id=sg_id))
        except vnc_exc.NoIdError:
            self._raise_contrail_exception(
                'SecurityGroupNotFound', id=sg_id, resource='security_group')

        self._resource_update(sg_obj)

        ret_sg_q = self._security_group_vnc_to_neutron(
            sg_obj, contrail_extensions_enabled)

        return ret_sg_q


class SecurityGroupCreateHandler(ResourceCreateHandler, SecurityGroupMixin):
    resource_create_method = "security_group_create"

    def _create_security_group(self, sg_q):
        project_id = self._project_id_neutron_to_vnc(sg_q['tenant_id'])
        try:
            project_obj = self._project_read(proj_id=project_id)
        except vnc_exc.NoIdError:
            raise self._raise_contrail_exception(
                'ProjectNotFound', project_id=project_id,
                resource='security_group')
        id_perms = vnc_api.IdPermsType(enable=True,
                                       description=sg_q.get('description'))
        sg_vnc = vnc_api.SecurityGroup(name=sg_q['name'],
                                       parent_obj=project_obj,
                                       id_perms=id_perms)
        return sg_vnc

    def resource_create(self, context, sg_q):
        from neutron_plugin_contrail.plugins.opencontrail.vnc_client.sgrule_res_handler import SecurityGroupRuleHandler

        contrail_extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)
        sg_obj = self._security_group_neutron_to_vnc(
            sg_q,
            self._create_security_group(sg_q))

        # ensure default SG and deny create if the group name is default
        if sg_q['name'] == 'default':
            self._ensure_default_security_group_exists(sg_q['tenant_id'])
            self._raise_contrail_exception(
                "SecurityGroupAlreadyExists", resource='security_group')

        sg_uuid = self._resource_create(sg_obj)

        # allow all egress traffic
        def_rule_v4 = {
            'port_range_min': 0,
            'port_range_max': 65535,
            'direction': 'egress',
            'remote_ip_prefix': '0.0.0.0/0',
            'remote_group_id': None,
            'protocol': 'any',
            'ethertype': 'IPv4',
            'security_group_id': sg_uuid,
        }
        SecurityGroupRuleHandler(self._vnc_lib).resource_create(context,
                                                                def_rule_v4)

        def_rule_v6 = {
            'port_range_min': 0,
            'port_range_max': 65535,
            'direction': 'egress',
            'remote_ip_prefix': None,
            'remote_group_id': None,
            'protocol': 'any',
            'ethertype': 'IPv6',
            'security_group_id': sg_uuid,
        }
        SecurityGroupRuleHandler(self._vnc_lib).resource_create(context,
                                                                def_rule_v6)

        ret_sg_q = self._security_group_vnc_to_neutron(
            sg_obj, contrail_extensions_enabled)
        return ret_sg_q


class SecurityGroupHandler(SecurityGroupGetHandler,
                           SecurityGroupCreateHandler,
                           SecurityGroupUpdateHandler,
                           SecurityGroupDeleteHandler):
    pass
