# User-API Documentation

The User-API provides user management over all controllers.

**Currently, all the calls must be made with BasicAuth in the request!**

## API Calls
- [/users](#users)
- [/users/[user]](#user)
- [/users/[user]/controllers](#controllers)
- [/users/[user]/controllers/[controller]](#controller)
- [/users/[user]/controllers/[controller]/models](#models)
- [/users/[user]/controllers/[controller]/models/[model]](#model)

## **/users** <a name="users"></a>
#### **Request type**: GET
* **Description**:
  Returns all of the information of all the users (with all their controller access and model access)
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
                     "type": "controller-type",
                     "access": "controller access",
                     "models": [{"name": "model-name",
                                 "access": "model access"}]
                   }]
  }]
  ```

#### **Request type**: POST
* **Description**:
  Creates a new user. Checks if the user exists.
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
                    "type": "controller-type",
                    "access": "controller access",
                    "models": [{"name": "model-name",
                                "access": "model access"}]
                  }]
  }
  ```

## **/users/[user]** <a name="user"></a>
#### **Request type**: GET
* **Description**:
  Gets the info of a user. Checks if the user exists.
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
                    "type": "controller-type",
                    "access": "controller access",
                    "models": [{"name": "model-name",
                                "access": "model access"}]
                  }]
  }
  ```

#### **Request type**: PUT
* **Description**:
  Changes the user password.
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
                    "type": "controller-type",
                    "access": "controller access",
                    "models": [{"name": "model-name",
                                "access": "model access"}]
                  }]
  }
  ```

#### **Request type**: DELETE
* **Description**:
  Removes the user.
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
                     "type": "controller-type",
                     "access": "controller access",
                     "models": [{"name": "model-name",
                                 "access": "model access"}]
                   }]
  }]
  ```

## **/users/[user]/controllers** <a name="controllers"></a>
#### **Request type**: GET
* **Description**:
  Gives all the controllers the user has access to, with the access level
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - access
* **Successful response**:
  - code: 200
  - message:
  ```json
  [{"name": "controller-name",
    "type": "controller-type",
    "access": "controller access",
    "models": [{"name": "model-name",
                "access": "model access"}]
  }]
  ```

## **/users/[user]/controllers/[controller]** <a name="controller"></a>
#### **Request type**: GET
* **Description**:
  Gives the users access to this controller and it's models it has access to
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "controller-name",
   "type": "controller-type",
   "access": "controller access",
   "models": [{"name": "model-name",
               "access": "model access"}]
  }
  ```

#### **Request type**: PUT
* **Description**:
  Gives a user the given access to a controller
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - access = {login | add-model | superuser}
* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "controller-name",
   "type": "controller-type",
   "access": "controller access",
   "models": [{"name": "model-name",
               "access": "model access"}]
  }
  ```

#### **Request type**: DELETE
* **Description**:
  Removes the user from the controller.
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
                     "type": "controller-type",
                     "access": "controller access",
                     "models": [{"name": "model-name",
                                 "access": "model access"}]
                   }]
  }]
  ```

## **/users/[user]/controllers/[controller]/models** <a name="models"></a>
#### **Request type**: GET
* **Description**:
  Shows the models a user has access to with his access level
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [{"name": "model-name",
    "access": "model access"}]
  }]
  ```

## **/users/[user]/controllers/[controller]/models/[model]** <a name="model"></a>
#### **Request type**: GET
* **Description**:
  Gets the access of the user to the model
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "model-name",
   "access": "model access"}
  ```

#### **Request type**: PUT
* **Description**:
    Gives a user the given access to a model
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - access = {read | write | admin}
* **Successful response**:
  - code: 200
  - message:
  ```json
  {"name": "model-name",
   "access": "model access"}
  ```

#### **Request type**: DELETE
* **Description**:
  Removes the user from the model.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [{"name": "model-name",
    "access": "model access"}]
  ```
