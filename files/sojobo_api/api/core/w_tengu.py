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
                spec, comp, data):
    if constraints:
        w_juju.check_constraints(constraints)
    if 'url' in data and w_juju.cloud_supports_series(controller.type, series):
        spec = 'ssh:ubuntu@{}'.format(data['url'])
    if w_juju.cloud_supports_series(controller.name, series):
        machine_manager.add_machine(username, password, controller, model.key, series, constraints, spec, comp)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines [POST] => Creating Machine!', controller.name, model.name)
        code, response = 202, 'Machine is being deployed!'
        return juju.create_response(code, response)
    else:
        code, response = 400, 'This cloud does not support this version of Ubuntu'
        LOGGER.error('/TENGU/controllers/%s/models/%s/machines [POST] => This cloud does not support this version of Ubuntu!', controller, model)
        return juju.create_response(code, response)
