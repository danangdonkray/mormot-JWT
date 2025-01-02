# JWT Authentication Project with Mormot

This project implements **JWT Authentication** using the **Mormot framework**. With JWT (JSON Web Token), the project provides a mechanism for user authentication through tokens, as well as access to various protected API endpoints.

## API Usage Example

### 1. **Request Token**
To obtain the JWT token, make a `GET` request to the following endpoint, passing `UserName` and `Password` as parameters:

- **URL**: `http://localhost:888/api/service/Auth`
- **Parameters**:
  - `UserName=User`
  - `Password=synopse`
    
### 1. **Refresh Token**
To get the refresh JWT token, make a `GET` request to the following endpoint, passing `UserName` and `Password` as parameters:

- **URL**: `http://localhost:888/api/service/RefreshToken`
- **Parameters**:
  - `UserName=User`
  - `Password=synopse`

This endpoint will return a JWT token that can be used for authentication in other API requests.

### 2. **Request Data**
Once you have the JWT token, you can access protected data. Use the JWT token you obtained earlier in the `Authorization` header to make requests to this endpoint:

- **URL**: `http://localhost:888/api/service/Sample.FullList`

This endpoint will return a list of protected data.

### 3. **Request Body JSON**
To send JSON data to the server through the API, use the following endpoint:

- **URL**: `http://localhost:888/api/service/Interface/tesjson`
- **Body** (JSON):
  ```json
  {
    "key1": "value1",
    "key2": "value2"
  }
