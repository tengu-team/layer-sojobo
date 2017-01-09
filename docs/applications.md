**/controllers/`<controller>`/models/`<model>`/applications/`<application>`**
* Request type: GET, DELETE
* Required data: api_key

**/controllers/`<controller>`/models/`<model>`/applications/**
* Request type: POST
* Required data: api_key, application
* Optional data: series, machine **NOT TESTED**

Application is the application name. When prefixed with `local:` it will look in the local charm dir (on the server) as defined
in the charm config **NOT TESTED**. Otherwise it will look in the Juju Charm Store

**/controllers/`<controller>`/models/`<model>`/applications/`<application>`/units**
* Request type: POST
* Required data: api_key

**/controllers/`<controller>`/models/`<model>`/applications/`<application>`/units/`<unitnumber>`**
* Request type: GET, DELETE
* Required data: api_key

The unitnumber is the part after the `/` in the name of the unit. **ToDo: remove app-name from unitname for consistency**

**TODO: /controllers/`<controller>`/models/`<model>`/bundles**
* Request type: POST
* Required data: api_key, file (multipart/form instead of application/json)
