from subprocess import Popen
import json
import hashlib

from sojobo_api import settings


class ModelObject:
    def __init__(self, key, name, state, uuid, credential_name):
        self.key = key
        self.name = name
        self.state = state
        self.uuid = uuid
        self.credential_name = credential_name


def construct_model_key(c_name, m_name):
    key_string = c_name + "_" + m_name
    # Must encode 'key_string' because base64 takes 8-bit binary byte data.
    m_key = 'm{}'.format(hashlib.md5(key_string.encode('utf')).hexdigest()[:-1])
    # To return a string you must decode the binary data.
    return m_key

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
