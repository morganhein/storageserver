package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
	"github.com/morganhein/simplestorageserver/datastore"
	"github.com/nu7hatch/gouuid"
)

func init() {
	err := datastore.MakeDB()
	if err != nil {
		panic(err)
	}
}

func sendError(w http.ResponseWriter, code int, err string) {
	sendJSONResponse(w, code, struct {
		Error string `json:"error"`
	}{err})
}

func sendJSONResponse(w http.ResponseWriter, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		j, err := json.Marshal(data)
		if err != nil {
			//log it
			log.Println(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(j)
	}
}

//This endpoint is used to register as a new user.
//Usernames must be at least 3 characters and no more than 20,
//and may only contain alphanumeric characters. Passwords must be at least 8 characters.
//Response success: 204. Response failure: 400 w/ json "error"
func register(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sendError(w, 400, err.Error())
		return
	}
	var t datastore.User
	if err = json.Unmarshal(body, &t); err != nil {
		sendError(w, 400, err.Error())
		return
	}

	if len(t.Username) < 3 || len(t.Username) > 20 {
		sendError(w, 400, "username length must be 3-20 characters long")
	}

	if len(t.Password) < 8 {
		sendError(w, 400, "password must be at least 8 characters long")
	}
	//check if username exists already
	tx := datastore.DB.Txn(false)
	defer tx.Abort()

	user, err := tx.First("users", "id", t.Username)
	defer tx.Abort()
	if err != nil {
		sendError(w, 400, err.Error())
		return
	}
	if user != nil {
		sendError(w, 400, "username already exists")
		return
	}

	//save user to db
	tx = datastore.DB.Txn(true)
	if err = tx.Insert("users", &t); err != nil {
		sendError(w, 400, err.Error())
		return
	}
	tx.Commit()

	//success
	w.WriteHeader(204)
}

//This endpoint is used to log in as an existing user.
//On success, it returns a session token.
//The session token should be included in future requests to authenticate the sender.
//Response success: 200. Response failure: 403 Forbidden w/ json "error"
func login(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sendError(w, 403, err.Error())
		return
	}
	var t datastore.User
	if err = json.Unmarshal(body, &t); err != nil {
		sendError(w, 403, err.Error())
		return
	}

	if len(t.Username) == 0 || len(t.Password) == 0 {
		sendError(w, 403, "username or password is blank")
		return
	}

	//check if username exists
	tx := datastore.DB.Txn(false)
	defer tx.Abort()

	raw, err := tx.First("users", "id", t.Username)
	defer tx.Abort()
	if err != nil {
		sendError(w, 403, err.Error())
		return
	}
	if raw == nil {
		sendError(w, 403, "username/password combination incorrect")
		return
	}
	user := raw.(*datastore.User)
	if t.Password != user.Password {
		sendError(w, 403, "username/password combination incorrect")
		return
	}

	//generate token and save
	u, err := uuid.NewV4()
	if err != nil {
		sendError(w, 403, err.Error())
		return
	}

	sess := datastore.Session{
		Token:    u.String(),
		Username: user.Username,
	}

	tx = datastore.DB.Txn(true)
	if err = tx.Insert("sessions", &sess); err != nil {
		sendError(w, 403, err.Error())
		return
	}
	tx.Commit()

	sendJSONResponse(w, 200, struct {
		Token string `json:"token"`
	}{sess.Token})
}

//detectLogin determines if a user is logged in with the supplied token
func detectLogin(r *http.Request) (string, error) {
	token := r.Header.Get("X-Session")
	if len(token) == 0 {
		return "", errors.New("missing session token")
	}
	//check if that's a valid session id
	tx := datastore.DB.Txn(false)
	defer tx.Abort()

	raw, err := tx.First("sessions", "id", token)
	defer tx.Abort()
	if err != nil {
		return "", err
	}
	if raw == nil {
		return "", errors.New("session token invalid")
	}
	user := raw.(*datastore.Session)
	//return the user it belongs to
	return user.Username, nil
}

//storeFile stores a file to the logged-in user's personal storage.
func storeFile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := detectLogin(r)
	if err != nil {
		sendError(w, 403, "not logged in")
		return
	}

	f := datastore.File{
		Filename:    ps.ByName("filename"),
		Username:    user,
		ContentType: r.Header.Get("Content-Type"),
	}
	l := r.Header.Get("Content-Length")

	li, err := strconv.Atoi(l)
	if err != nil {
		sendError(w, 400, err.Error())
	}

	f.Data = make([]byte, li)
	read, err := r.Body.Read(f.Data)
	if read == 0 {
		sendError(w, 400, "file was empty")
		return
	}

	tx := datastore.DB.Txn(true)
	if err = tx.Insert("files", &f); err != nil {
		sendError(w, 400, err.Error())
		return
	}
	tx.Commit()

	w.WriteHeader(200)
	w.Header().Set("Location", "/files/"+f.Filename)
}

//deleteFile deletes the file specified by this user, if owned by them.
func deleteFile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := detectLogin(r)
	if err != nil {
		sendError(w, 403, "not logged in")
		return
	}
	file := ps.ByName("filename")
	tx := datastore.DB.Txn(false)
	defer tx.Abort()

	raw, err := tx.First("files", "id", file, user)
	if raw == nil {
		sendError(w, 404, "file not found")
		return
	}
	tx.Abort()

	tx = datastore.DB.Txn(true)
	err = tx.Delete("files", raw)
	if err != nil {
		sendError(w, 400, err.Error())
		return
	}

	tx.Commit()
	w.WriteHeader(204)
}

//getFile returns the file requested by this user
func getFile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := detectLogin(r)
	if err != nil {
		sendError(w, 403, "not logged in")
		return
	}
	file := ps.ByName("filename")
	tx := datastore.DB.Txn(false)
	defer tx.Abort()

	raw, err := tx.First("files", "id", file, user)
	if raw == nil {
		sendError(w, 404, "file not found")
		return
	}
	tx.Abort()
	f := raw.(*datastore.File)
	l := strconv.Itoa(len(f.Data))
	w.WriteHeader(200)
	w.Header().Set("Content-Length", l)
	w.Header().Set("Content-Type", f.ContentType)
	w.Write(f.Data)
}

//getFiles lists all the files owned by this user
func getFiles(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user, err := detectLogin(r)
	if err != nil {
		sendError(w, 403, "not logged in")
		return
	}
	tx := datastore.DB.Txn(false)
	fi, err := tx.Get("files", "user", user)
	if err != nil {
		sendError(w, 400, err.Error())
		return
	}
	files := make([]string, 0)
	if next := fi.Next(); next != nil {
		files = append(files, next.(*datastore.File).Filename)
	}
	resp, err := json.Marshal(files)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func main() {
	router := httprouter.New()
	router.POST("/register", register)
	router.POST("/login", login)
	router.PUT("/files/:filename", storeFile)
	router.DELETE("/files/:filename", deleteFile)
	router.GET("/files/:filename", getFile)
	router.GET("/files", getFiles)

	log.Fatal(http.ListenAndServe(":8089", router))
}
