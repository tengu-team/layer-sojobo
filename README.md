# Introduction
This is the api for the Tengu platform. Besides providing all the necessary Tengu - commands, it also introduces
JuJu - wide users (instead of users on a controller-level) and the principle of an admin-user.
# Installation
In order to use the api, at least one controller must be installed alongside the sojobo-api.

Assuming all your build charms are in the same directory, and you are in that directory, the installation process is:
* `juju deploy ./sojobo-api`
* `juju deploy ./controller-<type>` e.g. `juju deploy ./controller-aws`
* `juju add-relation sojobo-api controller-<type>` e.g. `juju add-relation sojobo-api controller-aws`
* `juju expose sojobo-api`

# API
The entire api is modular: extra modules will be loaded automatically if placed in the api-folder, provided they
follow the naming rules and provide the required functions.

## Error codes
The API return the following error codes:
- **400**: When the request does not contain the required data, has forbidden characters or the provided option/access-level does not exist
- **401**: When a user has no access to a certain resource
- **403**: API-key mismatch
- **404**: When a specific resource does not exists
- **405**: When a user has access to the resource, but the operation is not permitted
- **409**: When a resource already exists
- **500**: When the Sojobo, despite all its wisdom and knowledge fails

## Tengu - api
This api is used to control Juju controllers, models, applications, relations and machines. All it's calls are available under
`http://host/tengu/<call>` and are protected with basic-Authentication. The username is `admin` and the password is set with
the charm config.

## API-modules
The api is written in Flask. This allows the use of blueprints to expand the api. API-modules file names must follow
this scheme: `api_<modulename>.py`. The modulename MAY NOT contain an underscore. The module itself must have the following
inside:
```python
<MODULENAME> = Blueprint(<modulename>, __name__)


def get():
    return <MODULENAME>
```

## Controller-modules
Controller modules name must follow this scheme: `controller_<controllername>.py` and must be placed in the controller folder.
The controllername MAY NOT contain an underscore. The module itself must have the following inside:
```python
class Token(object):
    def __init__(self, url, username, password):
        self.type = <juju_controller_type>
        self.supportlxd = True
        self.url = url


def create_controller(name, region, credentials):
    ...
    return check_output(['juju', 'bootstrap', cloudname, name])


def get_supported_series():
    return ['trusty', 'xenial']
```

* A Token object, which has the controller type in lowercase, whether or not it supports lxd containers, the url of the endpoint, the required information to log into the controller (username, password, api_key, etc.). The Token objects must have the `get_credentials` and `get_cloud` functions, which return the required JuJu-styled data.
* A `create_controller(name, region, credentials)` function, which houses all the required code required to successfully bootstrap a controller of this type.
* A `get_supported_series()` function which returns a list of Ubuntu-versions this controller can deploy.

# Documentation
Documentation of the api can be found under [docs](docs).  

# Bugs
Report bugs on <a href="https://github.com/Qrama/Sojobo-api/issues">Github</a>

# Author
Mathijs Moerman <a href="mailto:mathijs.moerman@qrama.io">mathijs.moerman@qrama.io</a>
