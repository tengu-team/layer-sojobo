import subprocess

from sojobo_api import settings


class ModelObject:
    def __init__(self, key, name, state, uuid, credential_name):
        self.key = key
        self.name = name
        self.state = state
        self.uuid = uuid
        self.credential_name = credential_name

def add_relation(controller_key, endpoint, cacert,  model_name,
                 model_uuid, juju_username, password, relation1, relation2):
    """Executes background script that adds a relation between two applications in a model.

    :param controller_name: The name of the controller where the model resides.
    :type name: str.
    :param endpoint: IP-address of controller endpoint.
    :type state: str.

    """
    subprocess.Popen(["python3", "{}/scripts/add_relation.py".format(settings.SOJOBO_API_DIR),
                      controller_key, endpoint, cacert, model_name, model_uuid,
                      juju_username, password, relation1, relation2])
