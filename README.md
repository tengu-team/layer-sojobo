# Introduction
This is the api for the [Tengu](http://tengu.io) platform. 

# Installation
To deploy the api in your Juju environment, execute the following steps:
```
juju deploy cs:~tengu-team/sojobo-api
juju deploy arangodb
juju add-relation sojobo-api arangodb
```
To setup your environment, you will have to provide your cloud-credentials that can be used to deploy workspaces on your cloud infrastructure. Currently the Tengu platform supports 3 Cloud operators: AWS, Google CE and Azure.
Each cloud environment has its own subordinate charm, containing some cloud-specific workflows.

### Google GCE Setup
```
juju deploy .cs:~tengu-team/controller-google
juju add-relation sojobo-api controller-google
juju config sojobo-api cloud-region="europe-west1"
juju config sojobo-api cloud-type="google"
juju config sojobo-api cloud-credential="{'private_key_id': xxx, 'client_id': xxxx, 'token_uri': xxx, 'auth_uri': xxxx, 'type': xxxx, 'auth_provider_x509_cert_url': xxxx, 'client_x509_cert_url': xxx, 'client_email': xxx, 'private_key': xxxx, 'project_id': xxx}"
```

### AWS Setup
```
juju deploy .cs:~tengu-team/controller-aws
juju add-relation sojobo-api controller-aws
juju config sojobo-api cloud-region="eu-west-1"
juju config sojobo-api cloud-type="aws"
juju config sojobo-api cloud-credential="{'access-key': xxxxx, 'secret-key': xxx}"
```

### Azure Setup
```
juju deploy .cs:~tengu-team/controller-azure
juju add-relation sojobo-api controller-azure
juju config sojobo-api cloud-region="northeurope"
juju config sojobo-api cloud-type="azure"
juju config sojobo-api cloud-credential="{'application-id': xxxx, 'application-password': xxxx, 'subscription-id': xxx}"
```


When installation is completed, you can see the status of the installed sojobo-api by doing a get request to the root url. If everything is running, the response will look like this:
```json
  {
    "version": "0.18.0",
    "used_apis": ["api_tengu", "api_users", "api_bundles", "api_companies"],
    "controllers": ["controller_google"]
  }
```

# API
The entire api is modular: extra modules will be loaded automatically if placed in the api-folder, provided they
follow the naming rules and provide the required functions. The Documentation of the API can be found [here](https://github.com/tengu-team/layer-sojobo/wiki).

## API-modules
The api is written in Flask. This allows the use of blueprints to expand the api. API-modules file names must follow
this scheme: `api_<modulename>.py`. The modulename MAY NOT contain an underscore. The module itself must have the following
inside:
```python
<MODULENAME> = Blueprint(<modulename>, __name__)


def get():
    return <MODULENAME>
```


# Documentation
Documentation of the api can be found under the Wiki Tab of this repository.  

# Bugs
Report bugs on [Github](https://github.com/tengu-team/layer-sojobo/issues)

# Authors
- Sébastien Pattyn <sebastien.pattyn@tengu.io>
- Michiel Ghyselinck <michiel.ghyselinck@tengu.io>
