from subprocess import Popen
import json

from sojobo_api import settings


class ModelObject:
    def __init__(self, key, name, state, uuid, credential_name):
        self.key = key
        self.name = name
        self.state = state
        self.uuid = uuid
        self.credential_name = credential_name


def add_relation(endpoint, cacert, model_uuid, juju_username, password,
                 relation1, relation2):
    """Executes background script that adds a relation between two applications in a model."""
    Popen(["python3",
           "{}/scripts/add_relation.py".format(settings.SOJOBO_API_DIR),
           endpoint, cacert, model_uuid, juju_username, password,
           relation1, relation2])


def add_application(endpoint, ca_cert, model_key, model_uuid, juju_username,
                    password, units, machine, config, application, series):
    serie = '' if series is None else str(series)
    target = '' if machine is None else str(machine)
    Popen(["python3",
           "{}/scripts/add_application.py".format(settings.SOJOBO_API_DIR),
           endpoint, ca_cert, model_key, model_uuid, juju_username, password,
           units, target, str(json.dumps(config)), application, serie])
