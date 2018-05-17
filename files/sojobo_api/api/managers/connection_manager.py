import asyncio
import json
import datetime
from random import randint

from juju.controller import Controller
from juju.errors import JujuAPIError
from flask import Response

from sojobo_api.api.core import w_errors as errors, authentication
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api.managers import (
    user_manager,
    controller_manager,
    model_manager,
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
    if authorization:
        company = datastore.get_company_user(authorization.username)
        if company:
            company_name = company['company']
            company_access = company['company_access']['is_admin']
        else:
            company_name = None
            company_access = None

        if controller_name:
            controller_key = controller_manager.construct_controller_key(
                        controller_name, company_name)
            if model_name:
                model_key = model_manager.construct_model_key(
                            controller_name, model_name)
                info_data = datastore.get_model_connection_info(
                            authorization.username, controller_key, model_key)
            else:
                info_data = datastore.get_controller_connection_info(
                            authorization.username, controller_key)
        else:
            info_data = datastore.get_user_connection_info(
                        authorization.username)

        validation_test(authorization, info_data)

        objects = create_objects(authorization, info_data, company_name,
                                 company_access)

        if 'controller' in objects:
            if 'model' in objects:
                return objects['user'], objects['controller'], objects['model']
            return objects['user'], objects['controller']
        return objects['user']

    else:
        raise ValueError(errors.unauthorized())


def validation_test(authorization, data):
    validation_test_user(data)
    if "controller" in data:
        validation_test_controller(authorization, data)
    if "model" in data:
        validation_test_model(data)


def validation_test_user(data):
    """Performs validation tests on user data.

    :param data: Data about a user, retrieved from database.
    :type name: dict.

    :raises: ValueError
    """
    if data["user"]:
        if data['user']['state'] == 'pending':
            error = ('The user is not ready yet to perform this action. '
                     'Please wait untill the user is created!')
            raise ValueError(403, error)
        elif data['user']['state'] != 'ready':
            error = ('The user is being removed and not able to perform  '
                     'this action anymore!.')
            raise ValueError(403, error)
    else:
        error = errors.unauthorized()
        raise ValueError(error[0], error[1])


def validation_test_controller(authorization, data):
    """Performs validation tests on controller data.

    Checks if the controller, that the user of the API wants to use,
    exist and is ready. If the controller does not exist then only the
    admin user should be allowed to know that fact.

    :param authorization: Contains a username and password of user.
    :type authorization: dict.
    :param data: Data about a user, retrieved from database.
    :type name: dict.

    :raises: ValueError
    """
    if data['controller']:
        if data['controller']['state'] != 'ready':
            error = ('The environment is not ready yet. '
                     'Please wait untill the environment is created!')
            raise ValueError(409, error)
    elif authentication.check_if_admin(authorization):
        error = errors.does_not_exist('environment')
        raise ValueError(error[0], error[1])
    else:
        error = errors.unauthorized()
        raise ValueError(error[0], error[1])


def validation_test_model(data):
    """Performs validation tests on model data.

    Checks the state of a model and returns an appropriate message if it
    cannot be used yet (f.e. when it is in pending state).

    :param data: Data about a model, retrieved from database.
    :type name: dict.

    :raises: ValueError
    """
    if data['model'] and data['m_access']:
        state = data['model']['state']
        if state == 'accepted':
            error = ('The workspace is not ready yet.'
                     'Please wait untill the workspace is created!')
            raise ValueError(409, error)
        elif state == 'deleting':
            raise ValueError(409, "The workspace is being removed!")
        elif state != 'ready':
            raise ValueError(409, "Model in error state => {}".format(state))
    elif data['c_access'] in ['superuser', 'add_model', 'admin']:
        error = errors.does_not_exist('workspace')
        raise ValueError(error[0], error[1])
    else:
        error = errors.unauthorized()
        raise ValueError(error[0], error[1])


def create_objects(authorization, data, company_name, company_access):
    objects = {}

    objects["user"] = create_user_object(data, authorization.username,
                                         authorization.password, company_name,
                                         company_access)
    if 'controller' in data:
        objects['controller'] = create_controller_object(data["controller"])
    if 'model' in data:
        objects['model'] = create_model_object(data["model"])

    return objects


def create_user_object(data, username, password, company_name,
                       company_access):
    return user_manager.UserObject(
        username=username,
        password=password,
        juju_username=data['user']['juju_username'],
        controller_access=data.get('c_access', None),
        model_access=data.get('m_access', None),
        company=company_name,
        company_admin=company_access,
        ssh_keys=data['user']['ssh_keys'],
        credentials=data['user']['credentials'])


def create_controller_object(controller_data):
    return controller_manager.ControllerObject(
        key=controller_data['_key'],
        name=controller_data['name'],
        state=controller_data['state'],
        type=controller_data['type'],
        region=controller_data['region'],
        models=controller_data['models'],
        endpoints=controller_data['endpoints'],
        uuid=controller_data['uuid'],
        ca_cert=controller_data['ca_cert'],
        default_credential_name=controller_data['default-credential']
    )


def create_model_object(model_data):
    return model_manager.ModelObject(
        key=model_data['_key'],
        name=model_data['name'],
        state=model_data['state'],
        uuid=model_data['uuid'],
        credential_name=model_data['credential']
    )
