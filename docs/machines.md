**/controllers/`<controller>`/models/`<model>`/machines/**
* Request type: GET, POST
* Required header: api-key
* Optional data: series **NOT TESTED**

When passed a series in a post-request, the api will check if the cloud supports this series of Ubuntu. If yes, it will create the machine with the requested series.

**/controllers/`<controller>`/models/`<model>`/machines/`<machine>`**
* Request type: GET, DELETE
* Required header: api-key
