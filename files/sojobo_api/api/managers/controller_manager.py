

class ControllerObject:
    def __init__(self, key, name, state, type, region, models, endpoints, uuid,
                 ca_cert, default_credential_name):
        self.key = key
        self.name = name
        self.state = state
        self.type = type
        self.region = region
        self.models = models
        self.endpoints = endpoints
        self.uuid = uuid
        self.ca_cert = ca_cert
        self.default_credential_name = default_credential_name
