#Go Neo4j RESTful Auth Example

This repository contains a simple Go program demonstrating a RESTful API with user registration and authentication capabilities utilizing a Neo4j graph database.

## Prerequisites

You must have:

* Go setup: [https://golang.org/doc/install](https://golang.org/doc/install)
* Neo4j setup: [http://neo4j.com/developer/get-started/](http://neo4j.com/developer/get-started/)

## Implementation notes

* Authentication is implemented with a JSON Web Token (JWT).
* Password hashes are generating by prepending individual unique salt, and bcrypting this salt prepended to the submitted password.
* The salt and password hash are stored as paramters to a Person node in the Neo4j database.

## Example commandline interaction via  (replace ALLCAPS values as required):

Register new user:

	curl -d '{"email": "EMAIL@SOMEWHERE.COM", "password": "PASSWORD"}' -H "Content-Type:application/json" http://localhost:8080/api/register

Authenticate registered user:

	curl -d '{"username": "EMAIL@SOMEWHERE.COM", "password": "PASSWORD"}' -H "Content-Type:application/json" http://localhost:8080/api/login

Get currently logged in user:

	curl -H "Authorization:Bearer JWTOKEN_RETURNED_FROM_LOGIN_REQUEST" http://localhost:8080/api/auth_test

Refresh JWT token:

	curl -H "Authorization:Bearer JWTOKEN_RETURNED_FROM_LOGIN_REQUEST" http://localhost:8080/api/refresh_token
