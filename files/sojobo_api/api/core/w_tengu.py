from sojobo_api.api import w_juju
from sojobo_api.api.managers import machine_manager, model_manager

"""This module holds logic that does not belong in api_tengu."""


def add_relation(controller, model, juju_username,
                 password, relation1, relation2, model_connection):
    app1_name, app2_name = relation1, relation2
    if ':' in app1_name:
        app1_name = app1_name.split(':')[0]
    if ':' in app2_name:
        app2_name = app2_name.split(':')[0]

    if w_juju.app_exists(model_connection, app1_name):
        if w_juju.app_exists(model_connection, app2_name):
            model_manager.add_relation(controller.key, controller.endpoints[0],
                                       controller.ca_cert, model.name,
                                       model.uuid, juju_username, password,
                                       relation1, relation2)
        else:
            raise ValueError(app2_name)
    else:
        raise ValueError(app1_name)


def add_machine(controller, model, username, password, series, constraints,
                spec, company, url):
    if constraints:
        w_juju.check_constraints(constraints)
    if url and w_juju.cloud_supports_series(controller.type, series):
        spec = 'ssh:ubuntu@{}'.format(url)
    if w_juju.cloud_supports_series(controller.name, series):
        machine_manager.add_machine(username, password,
                                    controller.name, model.key, series,
                                    constraints, spec, company)


def get_machine(connection, machine):
    machine_manager.get_machine(connection, machine)
