import hashlib

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

def construct_controller_key(c_name, company):
    if not company:
        return c_name
    else:
        key_string = c_name + "_" + company
        # Must encode 'key_string' because base64 takes 8-bit binary byte data.
        m_key = 'c{}'.format(hashlib.md5(key_string.encode('utf')).hexdigest()[:-1])
        # To return a string you must decode the binary data.
        return m_key
