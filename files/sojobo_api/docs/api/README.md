# Info
The `sojobo_api.py` script is responsible for starting the api. It will load the api blueprints (`api_<modulename>.py`)
and register them under `/<modulename>`. It also sets the necessary access-control values and content types. A code 403
error handler is provided.

# General working
Every call of the api returns a json `{'message': '<response>'}`, unless otherwise specified in the documentation

# Routes
* `/`
  * HTTP Method: ALL
  * Required data: None
  * Response codes:
    * 200: `{'name': <name>, 'version': <version>, 'api_dir': <api_dir>, 'used_apis': <loaded_blueprints>}`
* `/favicon.ico`
  * HTTP Method: ALL
  * Required data: None
  * Response codes:
    * 302: redirect to the Tengu icon
