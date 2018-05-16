import theblues

from sojobo_api.api import w_juju
from sojobo_api.api.core import w_errors as errors
from sojobo_api.api.managers import model_manager

"""This module holds logic that does not belong in api_tengu.

Validation checks are an example of logic that does not belong in api_tengu."""


def get_application_entity(application_name):
    """Retrieve metadata about an entity in the charmstore.

    :param application_name: The name of the application.
    :type name: str.
    :returns:  json -- metadata e.g. 'supported-series'.
    """
    cs = theblues.charmstore.CharmStore('https://api.jujucharms.com/v5')
    entity = cs.entity(application_name)
    return entity


def add_relation(controller, model, juju_username, password, relation1,
                 relation2, model_connection):
    app1_name, app2_name = relation1, relation2
    if ':' in app1_name:
        app1_name = app1_name.split(':')[0]
    if ':' in app2_name:
        app2_name = app2_name.split(':')[0]

    if w_juju.app_exists(model_connection, app1_name):
        if w_juju.app_exists(model_connection, app2_name):
            model_manager.add_relation(controller.key, controller.endpoints[0],
                                       controller.ca_cert, model.uuid,
                                       juju_username, password, relation1,
                                       relation2)
        else:
            raise ValueError(app2_name)
    else:
        raise ValueError(app1_name)


def deploy_application(connection, controller, model, username, password, units,
                       config, machine, application, series):
    try:
        get_application_entity(application)
    except theblues.errors.EntityNotFound:
        error = "The application '{}' cannot be found in the charm store!".format(application)
        raise ValueError(404, error)

    if not w_juju.app_exists(connection, application):
        if w_juju.cloud_supports_series(controller.type, series):
            if machine and not w_juju.machine_exists(connection, machine):
                error = errors.does_not_exist("machine %s".format(machine))
                raise ValueError(error[0], error[1])
            serie = '' if series is None else str(series)
            target = '' if machine is None else str(machine)
            model_manager.add_application(controller.key, model.key, username,
                                          password, units, target, config,
                                          application, serie)
        else:
            error = "The cloud \'{}\' does not support '{}' series.".format(controller.type, series)
            raise ValueError(400, error)
    else:
        error = errors.already_exists("application {}".format(application))
        raise ValueError(error[0], error[1])
