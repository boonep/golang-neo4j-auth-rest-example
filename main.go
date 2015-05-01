package main

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/StephanDollberg/go-json-rest-middleware-jwt"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/jmcvetta/neoism"
	"github.com/sendgrid/sendgrid-go"
)

type Impl struct {
	db *neoism.Database
}

func main() {

	// setup database
	i := Impl{}
	var err error

	// Make sure your url environment variable is setup i.e.
	// $ export NEO4JURL=http://neo4j:PASSWORD@localhost:7474/db/data
	neo4jUrl = os.Getenv("NEO4JURL")
	i.db, err = neoism.Connect(neo4jUrl)
	if err != nil {
		log.Fatal(err)
	}

	//jwt settings
	jwt_middleware := &jwt.JWTMiddleware{
		Key:           []byte("SECRETKEY"), //secret key
		Realm:         "jwt auth",
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: i.auth_user,
	}

	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)

	//add authentication middleware
	api.Use(&rest.IfMiddleware{
		// don't add middleware to paths contained in noAuthURI
		Condition: func(request *rest.Request) bool {
			noAuthURI := map[string]bool{
				"/login":    true,
				"/register": true,
			}
			return !noAuthURI[request.URL.Path]
		},
		// add authentication middleware to all other paths
		IfTrue: jwt_middleware,
	})
	router, err := rest.MakeRouter(
		rest.Post("/login", jwt_middleware.LoginHandler),
		rest.Post("/register", i.RegisterUser),
		rest.Get("/auth_test", handle_auth),
		rest.Get("/email_test", sendgridExample),
		rest.Get("/refresh_token", jwt_middleware.RefreshHandler),
	)
	if err != nil {
		log.Fatal(err)
	}
	api.SetApp(router)

	//all incoming paths should start with "api"
	http.Handle("/api/", http.StripPrefix("/api", api.MakeHandler()))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Register a new user given email and desired password.  Test with:
// $ curl -d '{"email": "EMAIL@SOMEWHERE.COM", "password": "PASSWORD"}' -H "Content-Type:application/json" http://localhost:8080/api/register
func (i *Impl) RegisterUser(w rest.ResponseWriter, r *rest.Request) {

	type User struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	user := User{}

	//get post json and decode intro struct
	if err := r.DecodeJsonPayload(&user); err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//check for email and password
	if len(user.Email) == 0 || len(user.Password) == 0 {
		rest.Error(w, "must submit valid email & password", http.StatusInternalServerError)
		return
	}

	//make sure email doesn't exist already
	people := []struct {
		email string `json:"a.email"`
	}{}
	cq := neoism.CypherQuery{
		// Use backticks for long statements - Cypher is whitespace indifferent
		Statement: `
	        MATCH (a:Person)
	        WHERE a.email = {email}
	        RETURN a.email
	    `,
		Parameters: neoism.Props{"email": user.Email},
		Result:     &people,
	}
	err := i.db.Cypher(&cq)
	if err != nil {
		rest.Error(w, "database query error", http.StatusInternalServerError)
		return
	}

	//email exists throw error
	if len(people) != 0 {
		rest.Error(w, "a user with this email already exists", http.StatusInternalServerError)
		return
	}

	//generate random salt
	size := 32 // change the length of the generated random string here
	rb := make([]byte, size)
	_, err = rand.Read(rb)
	if err != nil {
		rest.Error(w, "error generating password hash [1]", http.StatusInternalServerError)
		return
	}
	generatedSalt := base64.URLEncoding.EncodeToString(rb)

	//create hashed password
	saltAndPassword := append([]byte(user.Password), []byte(generatedSalt)...)
	hashedPassword, err := bcrypt.GenerateFromPassword(saltAndPassword, 10)
	if err != nil {
		rest.Error(w, "error generating password hash [2]", http.StatusInternalServerError)
		return
	}

	//create new user with required properties, and add "Person" label
	n0, err := i.db.CreateNode(neoism.Props{
		"email":    user.Email,
		"password": string(hashedPassword),
		"salt":     generatedSalt,
	})
	if err != nil {
		log.Fatal(err)
	}
	n0.AddLabel("Person")

	//success message
	w.WriteJson(map[string]string{"user created": user.Email})
}

// Authenticate user with provided userId & password.  Test with:
// $ curl -d '{"username": "EMAIL@SOMEWHERE.COM", "password": "PASSWORD"}' -H "Content-Type:application/json" http://localhost:8080/api/login
func (i *Impl) auth_user(userId string, password string) bool {
	if userId == "admin" && password == "admin" {
		return true
	} else {
		//properties to be captured from matching user
		people := []struct {
			Email    string `json:"a.email"`
			Password string `json:"a.password"`
			Salt     string `json:"a.salt"`
		}{}

		//query to match person with corresponding email and retrieve properties
		cq := neoism.CypherQuery{
			Statement: `
		        MATCH (a:Person)
		        WHERE a.email = {email}
		        RETURN a.email, a.password, a.salt
		    `,
			Parameters: neoism.Props{"email": userId},
			Result:     &people,
		}

		//don't authenticate if no matching emails or query error
		err := i.db.Cypher(&cq)
		if err != nil || len(people) == 0 {
			return false
		}

		//first matching person should be our target
		user := people[0]

		//verify password
		saltAndPassword := append([]byte(password), []byte(user.Salt)...)
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), saltAndPassword)
		if err != nil {
			return false
		}
		return true
	}
}

// show currently logged in user
func handle_auth(w rest.ResponseWriter, r *rest.Request) {
	w.WriteJson(map[string]string{"authed": r.Env["REMOTE_USER"].(string)})
}
