import json
import datetime
from Flask import Response
from sojobo_api.api.core import w_errors as errors
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api.managers import (
    user_manager,
    controller_manager,
    model_manager,
)


def give_timestamp():
    dt = datetime.datetime.now()
    dt_values = [dt.month, dt.day, dt.hour, dt.minute, dt.second]
    timestamp = str(dt.year)
    for value in dt_values:
        timestamp += str(value)
    return(timestamp)


def create_response(http_code, return_object, is_json=False):
    if not is_json:
        return_object = json.dumps(return_object)
    return Response(
        return_object,
        status=http_code,
        mimetype='application/json',
    )


def get_connection_info(authorization, controller_name=None, model_name=None):
    company = datastore.get_company_user(authorization.username)
    if company:
        company_name = company['company']
        company_access = company['company_access']['is_admin']
    else:
        company_name = None
        company_access = None
    if authorization:
        if controller_name:
            c_key = controller_manager.construct_controller_key(
                        controller_name, company_name)
            if model_name:
                m_key = model_manager.construct_model_key(
                            controller_name, model_name)
                info_data = datastore.get_model_connection_info(
                            authorization.username, c_key, m_key)
                model = model_manager.modelObject()
            else:
                info_data = datastore.get_controller_connection_info(
                            authorization.username, c_key)
            controller = controller_manager.controllerObject()
        else:
            info_data = datastore.get_user_connection_info(
                        authorization.username)
        user = user_manager.UserObject(
                    authorization.username,
                    authorization.password,
                    info_data['user']['juju_username'],
                    controller_access=info_data.get('c_access', None),
                    model_access=info_data.get('m_access', None),
                    company=company_name,
                    company_admin=company_access,
                    ssh_keys=info_data['user']['ssh-keys'],
                    credentials=info_data['user']['credentials'])
        if 'controller' in locals():
            if 'model' in locals():
                return user, controller, model
            return user, controller
        return user
    else:
        raise ValueError(errors.unauthorized())
