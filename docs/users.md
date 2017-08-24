# User-API Documentation

The User-API provides user management over all controllers.

**Currently, all the calls must be made with BasicAuth in the request!**

## API Calls
- [/users](#users)
- [/users/[user]](#user)
- [/users/[user]/ssh](#ssh)
- [/users/[user]/credentials](#credentials)
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
  {
          "name": "admin",
          "active": true,
          "credentials": [
              {
                  "name": "admin",
                  "type": "jsonfile",
                  "key": {
                      "file": "{"google_cred_file"}"
                  }
              }
          ],
          "ssh_keys": [
              null
          ],
          "access": [
              {
                  "testcontroller": {
                      "access": "superuser",
                      "models": [
                          {
                              "controller": "admin"
                          },
                          {
                              "default": "admin"
                          }
                      ],
                      "type": "google"
                  }
              }
          ]
      }
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
"User <username> succesfully created."
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
  {
          "name": "admin",
          "active": true,
          "credentials": [
              {
                  "name": "admin",
                  "type": "jsonfile",
                  "key": {
                      "file": "{"google_cred_file"}"
                  }
              }
          ],
          "ssh_keys": [
              null
          ],
          "access": [
              {
                  "testcontroller": {
                      "access": "superuser",
                      "models": [
                          {
                              "controller": "admin"
                          },
                          {
                              "default": "admin"
                          }
                      ],
                      "type": "google"
                  }
              }
          ]
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
"succesfully changed password for user admin"
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

## **/users/[user]/ssh** <a name="ssh"></a>
#### **Request type**: GET
* **Description**:
  Gets the SSH-keys of a user.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 202
  - message:
  ```json
  [
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJK2Cw67ZVIUF8XpYUHDY9jzCw7yH9LP4s501pgXQgFUn8ziyovNMdAST8XutgIYi0VVTjNhj4ZuQkwdqfpXBxibNIO9VTowqG0dsgsBLrJs7MhkMk0h/QxdyaV217yD0TSJdJo8X499rPvEuLVDFZzt2SSByuYESYJAuntDaEtMutA7Y2GtbwfCrSyNGqQa4YdbEcvMGWzlzQnQ8urIEljKFk95k+oV1m1GXqhAkai/qrfRGLmGUUreUIJgO06iWdrNfa6YVDMe5jM95YoDSzINLIbjm/+BV41BuLOJxdVLCz43d0zDhbBF4TJEpQUnNCv7V2FeWh3IC/atyB0SBD sebastien@sebastien-PC"
  ]
  ```

#### **Request type**: POST
* **Description**:
  Adds an SSH-key for a user.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - ssh-key
* **Successful response**:
  - code: 202
  - message:
  ```json
  "Process being handeled"
  ```

#### **Request type**: DELETE
* **Description**:
  Removes the users given SSH.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - ssh-key
* **Successful response**:
  - code: 202
  - message:
  ```json
  "Process being handeled"
  ```

## **/users/[user]/credentials** <a name="credentials"></a>
#### **Request type**: GET
* **Description**:
  Gets the credentials of a user.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 202
  - message:
  ```json
  [
      {
          "name": "credential1",
          "type": "jsonfile",
          "key": {
              "file": "{"credential_file1"}"
          }
      },
      {
          "name": "credential2",
          "type": "jsonfile",
          "key": {
              "file": "{"credential_file2"}"
          }
      }
  ]
  ```

#### **Request type**: POST
* **Description**:
  Adds an credential for a user.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - credentials
  - name
  - c_type
* **Successful response**:
  - code: 202
  - message:
  ```json
"Process being handeled"
  ```

#### **Request type**: DELETE
  * **Description**:
    Removes the users credential.
  * **Required headers**:
    - api-key
    - Content-Type:application/json
  * **Required body**:
    - name
  * **Successful response**:
    - code: 202
    - message:
    ```json
  "Process being handeled"
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
  [
      {
          "controller_name": {
              "access": "superuser",
              "models": [
                  {
                      "controller": "admin"
                  },
                  {
                      "default": "admin"
                  }
              ],
              "type": "google"
          }
      }
  ]
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
  {
      "controller_name": {
          "access": "superuser",
          "models": [
              {
                  "controller": "admin"
              },
              {
                  "default": "admin"
              }
          ],
          "type": "google"
      }
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
  - code: 202
  - message:
  ```json
  "Process being handeled"
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
