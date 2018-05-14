from sojobo_api.api import w_juju
from sojobo_api.api.managers import model_manager

"""This module holds logic that does not belong in api_tengu."""

def add_relation(controller_key, endpoint, cacert, model_object, juju_username,
                 password, relation1, relation2, model_connection):
    app1_name, app2_name = relation1, relation2
    if ':' in app1_name:
        app1_name = app1_name.split(':')[0]
    if ':' in app2_name:
        app2_name = app2_name.split(':')[0]

    if w_juju.app_exists(model_connection, app1_name):
        if w_juju.app_exists(model_connection, app2_name):
            model_manager.add_relation(controller_key, endpoint, cacert, model_object,
                              juju_username, password, relation1, relation2)
        else:
            raise ValueError(app2_name)
    else:
        raise ValueError(app1_name)


def deploy_application(connection, controller, model, username, password, units,
                       config, machine, application, series):
    if not w_juju.app_exists(connection, application):
        if w_juju.cloud_supports_series(controller_type, series):
            if machine and not w_juju.machine_exists(connection, machine):
                error = errors.does_not_exist("machine %s".format(machine))
                raise ValueError(error)
            serie = '' if series is None else str(series)
            target = '' if machine is None else str(machine)
            model_manager.add_application(controller.key, model.key, username,
                                          password, units, target, config,
                                          application, serie)
        else:
            error = 400, "The cloud \'%s\' does not support '%s' series.".format(controller.type, series)
            raise ValueError(error)
    else:
        error = errors.already_exists("application %s".format(application))
        raise ValueError(error)
