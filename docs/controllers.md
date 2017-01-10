**/controllers**
* Request type: GET
* Required header: api-key

**/controllers**
* Request type: POST
* Required header: api-key
* Required data: controller, region, credentials
* Credentials are dependant of the type of controller. When the needed credentials are a file, a file must be send in a multipart/form request, with
the key 'file'. When no file is used, the required data is send as a json

**/controllers/`<controller>`**
* Request type: GET, DELETE
* Required header: api-key

ToDo: When no controllers are left, the 2 get-calls fail. So either prevent deleting all controllers, or expand the api with an initial setup
