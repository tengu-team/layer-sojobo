import asyncio
import json
import datetime
from random import randint
from juju.controller import Controller
from juju.errors import JujuAPIError

from flask import Response
from sojobo_api.api.core import w_errors as errors
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api.managers import (
    user_manager,
    controller_manager,
    model_manager,
)


def give_timestamp():
    '''
    This function will generate the current timestamp in the right format. This
    is used to add a timestamp to the juju_username. In that way, there will
    allways be an unique juju username.
    '''
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
    '''
    This function will query ArangoDB with all the required information to
    perform the required actions on the API.

    :param obj authorization: The basic auth object that was send to the api.
    :param str controller_name: The name of the controller on which the action
        will be performed(optional).
    :param str model_name: The name of the model on which the action will be
        performed(optional).
    '''
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
                    ssh_keys=info_data['user'].get('ssh-keys', None),
                    credentials=info_data['user'].get('credentials', None))
        if 'controller' in locals():
            if 'model' in locals():
                return user, controller, model
            return user, controller
        return user
    else:
        raise ValueError(errors.unauthorized())


async def connect_to_random_controller(user):
    '''
    This function will connect to a random controller to check if the provided
    username and password of the user are right.

    :param obj user: The UserObject of the User that is using the API.
    '''
    error = errors.unauthorized()
    try:
        ready_controllers = datastore.get_ready_controllers_with_access(
                    user.username, company=user.company)
        if len(ready_controllers) == 0:
            read_cons_no_acc = datastore.get_ready_controllers_no_access(
                        user.username, user.company)
            if len(read_cons_no_acc) > 0:
                user_manager.add_user_to_controllers(
                            user.username,
                            user.juju_username,
                            user.password,
                            user.company)
                raise ValueError(409, ('User {} is being added to the '
                                       'remaining environments').format(
                                       user.username))
            else:
                raise ValueError(400, ('Please wait untill your first '
                                       'environment is set up!'))
        else:
            con = ready_controllers[randint(0, len(ready_controllers) - 1)]
            controller_connection = Controller()
            await controller_connection.connect(endpoint=con['endpoints'][0],
                                                username=user.juju_username,
                                                password=user.password,
                                                cacert=con['ca_cert'])
            await controller_connection.disconnect()
    except JujuAPIError:
        raise ValueError(error[0], error[1])


def execute_task(command, *args, **kwargs):
    '''
    This function is a wrapper that will make it possible to get the event
    loop and start async functions.

    :param command: this is the async function that will have to be executed
        with his args and kwargs that are provided.
    '''
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    result = loop.run_until_complete(command(*args, **kwargs))
    return result
