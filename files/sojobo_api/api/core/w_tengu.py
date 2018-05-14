from sojobo_api.api import w_juju
from sojobo_api.api.managers import model_manager

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
