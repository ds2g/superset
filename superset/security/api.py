# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import logging
from typing import Any, Dict

from flask import request, Response
from flask_appbuilder import expose
from flask_appbuilder.api import BaseApi, safe
from flask_appbuilder.security.decorators import permission_name, protect
from flask_appbuilder.security.sqla.models import PermissionView
from flask_wtf.csrf import generate_csrf
from marshmallow import EXCLUDE, fields, post_load, Schema, ValidationError
from marshmallow_enum import EnumField

from flask_appbuilder.security.sqla.models import User
from superset import security_manager as sm, db
from superset.extensions import event_logger
from superset.security.guest_token import GuestTokenResourceType
from superset.models.user_tagroup import UserTAGroup
from superset.models.slice import slice_user
from superset.models.dashboard import (
    Dashboard,
    dashboard_slices,
    dashboard_user,
    DashboardRoles,
)

logger = logging.getLogger(__name__)


class PermissiveSchema(Schema):
    """
    A marshmallow schema that ignores unexpected fields, instead of throwing an error.
    """

    class Meta:  # pylint: disable=too-few-public-methods
        unknown = EXCLUDE


class UserSchema(PermissiveSchema):
    username = fields.String()
    first_name = fields.String()
    last_name = fields.String()


class ResourceSchema(PermissiveSchema):
    type = EnumField(GuestTokenResourceType, by_value=True, required=True)
    id = fields.String(required=True)

    @post_load
    def convert_enum_to_value(  # pylint: disable=no-self-use
        self, data: Dict[str, Any], **kwargs: Any  # pylint: disable=unused-argument
    ) -> Dict[str, Any]:
        # we don't care about the enum, we want the value inside
        data["type"] = data["type"].value
        return data


class RlsRuleSchema(PermissiveSchema):
    dataset = fields.Integer()
    clause = fields.String(required=True)  # todo other options?


class GuestTokenCreateSchema(PermissiveSchema):
    user = fields.Nested(UserSchema)
    resources = fields.List(fields.Nested(ResourceSchema), required=True)
    rls = fields.List(fields.Nested(RlsRuleSchema), required=True)


guest_token_create_schema = GuestTokenCreateSchema()


class SecurityRestApi(BaseApi):
    resource_name = "security"
    allow_browser_login = True
    openapi_spec_tag = "Security"

    @expose("/csrf_token/", methods=["GET"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def csrf_token(self) -> Response:
        """
        Return the csrf token
        ---
        get:
          description: >-
            Fetch the CSRF token
          responses:
            200:
              description: Result contains the CSRF token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        result:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        return self.response(200, result=generate_csrf())

    @expose("/guest_token/", methods=["POST"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("grant_guest_token")
    def guest_token(self) -> Response:
        """Response
        Returns a guest token that can be used for auth in embedded Superset
        ---
        post:
          description: >-
            Fetches a guest token
          requestBody:
            description: Parameters for the guest token
            required: true
            content:
              application/json:
                schema: GuestTokenCreateSchema
          responses:
            200:
              description: Result contains the guest token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        token:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            body = guest_token_create_schema.load(request.json)
            # todo validate stuff:
            # make sure the resource ids are valid
            # make sure username doesn't reference an existing user
            # check rls rules for validity?
            token = self.appbuilder.sm.create_guest_access_token(
                body["user"], body["resources"], body["rls"]
            )
            return self.response(200, token=token)
        except ValidationError as error:
            return self.response_400(message=error.messages)

    def custom_pvm_check(self, pvm: PermissionView, perm_name: str) -> bool:
        return str(pvm) == perm_name

    
    def create_role(self, role_name, datasourceIds, datasourceNames, isUser) -> None:
      pns = []
      for idx, id in enumerate(datasourceIds):
        pns.append('datasource access on [Tracking].[' + datasourceNames[idx] + '](id:' + id + ')')

      if isUser:
        pns.append('can write on Dataset')
        pns.append('can read on Dataset')
        pns.append('menu access on Dataset')
        pns.append('can save on Datasource')

      role = sm.add_role(role_name)
      pvms = sm.get_session.query(PermissionView).all()

      role.permissions = []
      for permission_view in pvms:
        for perm_name in pns:
          if self.custom_pvm_check(permission_view, perm_name):
            role.permissions.append(permission_view)
            break

      sm.get_session.merge(role)
      sm.get_session.commit()


    @expose("/test_this_user/", methods=["GET"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def ta_test_this_user(self) -> Response:
        return self.response(200, result=(g.user))


    @expose("/create_ta_user/", methods=["POST"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def ta_user_creation(self) -> Response:
        """
        Return the csrf token
        ---
        get:
          description: >-
            Fetch the CSRF token
          responses:
            200:
              description: Result contains the CSRF token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        result:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        data = request.json
        role_name = ''

        # admin, user, sub
        if data['type'] == 'admin':
          role_name = 'Admin'
        elif data['type'] == 'user':
          role_name = data['key']
        elif data['type'] == 'sub':
          role_name = data['key'] + '_sub'

        role = sm.find_role(role_name)

        if role is None:
          datasourceIds = data['datasourceIds'].split(',')
          datasourceNames = data['datasourceNames'].split(',')
          isUser = data['type'] == 'user'
          self.create_role(role_name, datasourceIds, datasourceNames, isUser)
        
        role_names = [role_name]
        if role_name != 'Admin':
          role_names.append('Gamma')

        user = sm.add_user(data['username'], 'DS2G', "User", data['email'], list(map(lambda rn:sm.find_role(rn), role_names)), password=data['password'])

        tagroup = 0
        if 'mainUserUsername' in data and data['mainUserUsername'] is not None:
          main_user_id = db.session.query(User.id).filter_by(username=data['mainUserUsername']).first()
          main_user_id = main_user_id[0]
          tagroup = db.session.query(UserTAGroup.tagroup).filter_by(user_id=main_user_id).first()
          tagroup = tagroup[0]
        else:
          tagroup = db.session.query(UserTAGroup.tagroup).order_by(UserTAGroup.tagroup.desc()).first()
          tagroup = tagroup[0]
          tagroup += 1

        utag_params = {'id': None, 'user_id': user.id, 'tagroup': tagroup}
        db.session.add(UserTAGroup(id=utag_params['id'], user_id=utag_params['user_id'], tagroup=utag_params['tagroup']))

        sm.get_session.commit()
        return self.response(200, id=user.id)

    @expose("/delete_ta_user/", methods=["POST"]) #DELETE
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def ta_user_deletion(self) -> Response:
        """
        Return the csrf token
        ---
        get:
          description: >-
            Fetch the CSRF token
          responses:
            200:
              description: Result contains the CSRF token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        result:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        data = request.json
        user = sm.find_user(data['username'])

        if user is not None:
          try:
            dashboards = db.session.query(Dashboard).filter_by(created_by_fk=user.id)
            for dashboard in dashboards:
              sm.get_session.execute(DashboardRoles.delete().where(DashboardRoles.c.dashboard_id == dashboard.id))
              sm.get_session.execute(dashboard_user.delete().where(dashboard_user.c.dashboard_id == dashboard.id))
              sm.get_session.execute(dashboard_slices.delete().where(dashboard_slices.c.dashboard_id == dashboard.id))
              sm.get_session.delete(dashboard)
            
            
            sm.get_session.execute(dashboard_user.delete().where(dashboard_user.c.user_id == user.id))
            sm.get_session.execute(slice_user.delete().where(slice_user.c.user_id == user.id))
            sm.get_session.delete(user)
            sm.get_session.commit()
          except SQLAlchemyError as ex:  # pragma: no cover
            sm.get_session.rollback()
            #raise DAODeleteFailedError(exception=ex)

        return self.response(200)

    @expose("/update_dataset_visibility/", methods=["PUT"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def update_dataset_visibility(self) -> Response:
        """
        Return the csrf token
        ---
        get:
          description: >-
            Fetch the CSRF token
          responses:
            200:
              description: Result contains the CSRF token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        result:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        data = request.json
        role = sm.find_role('Public')
        pns_add = []
        pns_remove = []

        for dataset in data['datasetsToUpdate']:
          ds_perm = 'datasource access on [Tracking].[' + dataset['name'] + '](id:' + dataset['id'] + ')'
          if dataset['public']:
            pns_add.append(ds_perm)
          else:
            pns_remove.append(ds_perm)
        
        pvms = sm.get_session.query(PermissionView).all()

        for permission_view in pvms:
          for perm_name in pns_add:
            if self.custom_pvm_check(permission_view, perm_name):
              role.permissions.append(permission_view)
              break
        
        for permission_view in pvms:
          for perm_name in pns_remove:
            if self.custom_pvm_check(permission_view, perm_name):
              role.permissions.remove(permission_view)
              break

        sm.get_session.merge(role)
        sm.get_session.commit()
        return self.response(200)