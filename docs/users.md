# ToDo
- Rewrite get_users_info function
- Add url's:
  - /users/user/controllers, get, gives the list of controllers with access and models
  - /users/user/controllers/controller, get, gives the access on this controller
  - /users/user/controllers/controller/models, get, gives the list of models of a controller
  - /users/user/controllers/controller/models/model, get, gives the access on this model

# User-API Documentation

The User-API provides user management over all controllers.

**Currently, all the calls must be made with BasicAuth in the request!**

## API Calls
- [/users](#users)
- [/users/[user]](#user)
- [/users/[user]/controllers/[controller]](#controller)
- [/users/[user]/controllers/[controller]/models/[model]](#model)

## **/users** <a name="users"></a>
#### **Request type**: GET
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [{"name": "username",
    "controllers": [{"name": "controller-name",
                     "access": "controller access",
                     "models": [{"name": "model-name",
                                 "access": "model access"}]
                   }]
  }]
  ```
* **Description**:
  Returns all of the information of all the users (with all their controller access and model access)

#### **Request type**: POST
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - username
  - password
* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "username",
   "controllers": [{"name": "controller-name",
                    "access": "controller access",
                    "models": [{"name": "model-name",
                                "access": "model access"}]
                  }]
  }
  ```
* **Description**:
  Creates a new user. Checks if the user exists.

## **/users/[user]** <a name="user"></a>
#### **Request type**: GET
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "username",
   "controllers": [{"name": "controller-name",
                    "access": "controller access",
                    "models": [{"name": "model-name",
                                "access": "model access"}]
                  }]
  }
  ```
* **Description**:
  Gets the info of a user. Checks if the user exists.

#### **Request type**: PUT
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - password
* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "username",
   "controllers": [{"name": "controller-name",
                    "access": "controller access",
                    "models": [{"name": "model-name",
                                "access": "model access"}]
                  }]
  }
  ```
* **Description**:
  Changes the user password.

#### **Request type**: DELETE
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [{"name": "username",
    "controllers": [{"name": "controller-name",
                     "access": "controller access",
                     "models": [{"name": "model-name",
                                 "access": "model access"}]
                   }]
  }]
  ```
* **Description**:
  Removes the user.

## **/users/[user]/controllers/[controller]** <a name="controller"></a>
#### **Request type**: PUT
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - access
* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "username",
   "controllers": [{"name": "controller-name",
                    "access": "controller access",
                    "models": [{"name": "model-name",
                                "access": "model access"}]
                  }]
  }
  ```
* **Description**:
  Gives a user the given access to a controller

#### **Request type**: DELETE
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [{"name": "username",
    "controllers": [{"name": "controller-name",
                     "access": "controller access",
                     "models": [{"name": "model-name",
                                 "access": "model access"}]
                   }]
  }]
  ```
* **Description**:
  Removes the user from the controller.

## **/users/[user]/controllers/[controller]/models/[model]** <a name="model"></a>
#### **Request type**: PUT
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - access
* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "username",
   "controllers": [{"name": "controller-name",
                    "access": "controller access",
                    "models": [{"name": "model-name",
                                "access": "model access"}]
                  }]
  }
  ```
* **Description**:
    Gives a user the given access to a model

#### **Request type**: DELETE
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [{"name": "username",
    "controllers": [{"name": "controller-name",
                     "access": "controller access",
                     "models": [{"name": "model-name",
                                 "access": "model access"}]
                   }]
  }]
  ```
* **Description**:
  Removes the user from the model.
