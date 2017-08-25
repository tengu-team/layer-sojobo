# Introduction
This is the api for the Tengu platform. Besides providing all the necessary Tengu - commands, it also introduces
JuJu - wide users (instead of users on a controller-level) and the principle of an admin-user.

Since it is still in beta, any suggestions and bugs are welcome on [Github](https://github.com/tengu-team/layer-sojobo/issues)

# Installation
The required charms can be found in the qrama-charms repo. In order to install these using the following commands, one must be in the topdir of the cloned qrama-charms repo.
```
juju deploy ./sojobo-api
juju deploy ./redis redis-server --series xenial
juju add-relation sojobo-api redis
```
Each cloud environment has its own subordinate charm, containing some cloud-specific workflows.
```
juju deploy ./controller-google
juju add-relation sojobo-api controller-google
```
When installation is completed, you can see the status of the installed sojobo-api by doing a get request to the root url. If everything is running, the response will look like this:
```json
  {
    "version": "1.0.0",
    "used_apis": ["api_tengu", "api_users"],
    "controllers": ["controller_google"]
  }
```
**Warning**
We are waiting on a bugfix in libjuju. In order to circumvent the problem for now, one must manually edit the model.py file of the juju package (`/usr/local/lib/python3.6/dist-packages/juju`).
L1293:
```python
  await self.revoke(username)
```
must be replaced with:
```python
  try:
      await self.revoke(username)
  except:
      pass
```


# API
The entire api is modular: extra modules will be loaded automatically if placed in the api-folder, provided they
follow the naming rules and provide the required functions.

## Tengu - api
This api is used to control Juju controllers, models, applications, relations and machines. All it's calls are available under
`http://host/tengu/<call>` and are protected with Basic-Authentication.

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
Report bugs on [Github](https://github.com/Qrama/Sojobo-api/issues)

# Authors
- Mathijs Moerman <mathijs.moerman@tengu.io>
- Sébastien Pattyn <sebastien.pattyn@tengu.io>
