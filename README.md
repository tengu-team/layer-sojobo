# Introduction
This is the api for the Tengu platform. Besides providing all the necessary Tengu - commands, it also introduces
JuJu - wide users (instead of users on a controller-level) and the principle of an admin-user.

Since it is still in beta, any suggestions and bugs are welcome on <a href="https://github.com/Qrama/Sojobo-api/issues">Github</a>

There is currently a rewrite in progress based on JuJu's python library <a href="https://github.com/juju/python-libjuju">libjuju</a>
# Installation

There are 3 different setup options that can be specified in the config:
- http (default)
- letsencrypt
- https

## http
This installs the service running on http. **This is highly discouraged!!!**

## letsencrypt

When choosing this option, the service configures itself so it can request LetsEncrypt certificates
Actual generating of the certificates **requires that the service is exposed and accessible on it's FQDN (Full Qualified Domain Name)**. This will also require setting the correct `host` config: ```juju config sojobo-api host=fqdn``` (without http:// or https:// prefix)

Generating the certificates is a manual operation, requiring to ssh to the machine on which the service is deployed.
The following command must be executed on that machine: ```sudo letsencrypt certonly -a webroot --webroot-path=[path_to_api] -d [fqdn] --rsa-key-size 4096```, with `fqdn` being the domain name.


## https
This option is used if the client already has its own SSL certifcates, or if they have been generated using LetsEncrypt.

It also requires manual execution of the following command on the machine on which the service is deployed (**make sure the output directory exists!**): ```sudo openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096``` This creates a DH-group for extra security. At the time of writing, 4096 is sufficient enough, but as time goes by, this number should be increased.
The output location can be changed, but then this must be passed to the config accordingly in the dhparam value. The charm itself will set the required permissions of the file.

More info of the process can be found <a href="https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-16-04">here</a>.
**Setting up the cronjob for automatic renewal of the certificates must also be done manually (see above url)!**
When the certificates are generated, one can continue setting up https by running the command (on the host-machine, not the application machine) ```juju config sojobo-api setup=https```.

### Own SSL certificates
For this the correct path for fullchain and privatekey must be provided in the config and the Nginx-user (www-data) must have read access to them.
The correct `host` config must be set: ```juju config sojobo-api host=fqdn``` (without http:// or https:// prefix)
### LetsEncrypt
After the config option `setup=letsencrypt` and manually generating the key, `setup=client` can be used, with fullchain and privatekey left to its default value (empty). The charm will then set the correct permissions and uses the default letsencrypt locations of the key.

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
- **500**: When the Sojobo, despite all its wisdom and knowledge, fails

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
