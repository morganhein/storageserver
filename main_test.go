package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"strconv"

	"github.com/julienschmidt/httprouter"
	"github.com/morganhein/simplestorageserver/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/tv42/mockhttp"
)

type jlogin struct {
	Token string `json:"token"`
}

//type rc struct {
//	bytes.Buffer
//}
//
//func (*rc) Close() error {
//	return nil
//}

func TestRegister(t *testing.T) {
	err := datastore.MakeDB()
	assert.NoError(t, err)
	//register(w http.ResponseWriter, r *http.Request, _ httprouter.Params)
	b := bytes.Buffer{}
	b.Write([]byte(`{"username":"user1", "password":"best_password"}`))
	req := mockhttp.NewRequest(t, "POST", "/register", &b)
	w := httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, w.Code, 204)

	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"user1", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/register", &b)
	w = httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, w.Code, 400)

	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"allthesmallthingstruecaretruthbrings", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/register", &b)
	w = httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, w.Code, 400)

	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"no", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/register", &b)
	w = httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, w.Code, 400)

	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"valid", "password":"invalid"}`))
	req = mockhttp.NewRequest(t, "POST", "/register", &b)
	w = httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, w.Code, 400)
}

func TestLogin(t *testing.T) {
	err := datastore.MakeDB()
	assert.NoError(t, err)
	//Register
	b := bytes.Buffer{}
	b.Write([]byte(`{"username":"user1", "password":"best_password"}`))
	req := mockhttp.NewRequest(t, "POST", "/register", &b)
	w := httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, w.Code, 204)
	//Login OK
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"user1", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/login", &b)
	w = httptest.NewRecorder()
	login(w, req, nil)
	assert.True(t, strings.Index(w.Body.String(), "token") != -1)

	//Register
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"user2", "password":"bestest_in_westest"}`))
	req = mockhttp.NewRequest(t, "POST", "/register", &b)
	w = httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, w.Code, 204)
	//User exists, wrong password
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"user2", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/login", &b)
	w = httptest.NewRecorder()
	login(w, req, nil)
	assert.True(t, strings.Index(w.Body.String(), "error") != -1)
	//User doesn't exist
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"nobody", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/login", &b)
	w = httptest.NewRecorder()
	login(w, req, nil)
	assert.True(t, strings.Index(w.Body.String(), "error") != -1)
	//User name is "archer". Obviously can't trust them.
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"archer", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/login", &b)
	w = httptest.NewRecorder()
	login(w, req, nil)
	assert.True(t, strings.Index(w.Body.String(), "error") != -1)
}

func TestDetectLogin(t *testing.T) {
	err := datastore.MakeDB()
	assert.NoError(t, err)
	//Register
	b := bytes.Buffer{}
	b.Write([]byte(`{"username":"user3", "password":"best_password"}`))
	req := mockhttp.NewRequest(t, "POST", "/register", &b)
	w := httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, 204, w.Code)

	//Login OK
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"user3", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/login", &b)
	w = httptest.NewRecorder()
	login(w, req, nil)
	var j jlogin
	err = json.Unmarshal(w.Body.Bytes(), &j)
	assert.NoError(t, err)
	assert.True(t, len(j.Token) > 0)

	//No user, missing x-session
	b = bytes.Buffer{}
	b.Write([]byte(""))
	req = mockhttp.NewRequest(t, "POST", "/files/dummyfile", &b)
	user, err := detectLogin(req)
	assert.Error(t, err)

	//x-session incorrect
	req.Header.Set("X-Session", "abc")
	user, err = detectLogin(req)
	assert.Error(t, err)

	//Detect user from x-session
	req.Header.Set("X-Session", j.Token)
	user, err = detectLogin(req)
	assert.NoError(t, err)
	assert.Equal(t, "user3", user)
}

func TestStoreFile(t *testing.T) {
	err := datastore.MakeDB()
	assert.NoError(t, err)
	//Register
	b := bytes.Buffer{}
	b.Write([]byte(`{"username":"user3", "password":"best_password"}`))
	req := mockhttp.NewRequest(t, "POST", "/register", &b)
	w := httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, 204, w.Code)

	//Login OK
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"user3", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/login", &b)
	w = httptest.NewRecorder()
	login(w, req, nil)
	var j jlogin
	err = json.Unmarshal(w.Body.Bytes(), &j)
	assert.NoError(t, err)
	assert.True(t, len(j.Token) > 0)

	data := bytes.Buffer{}
	data.Write([]byte("hello operator, i'm a dummy file"))
	req = mockhttp.NewRequest(t, "POST", "/files/dummy", &data)
	//req.Body = &data
	req.Header.Set("X-Session", j.Token)
	req.Header.Set("Content-Type", "VirtualFile")
	l := strconv.Itoa(data.Len())
	req.Header.Set("Content-Length", l)
	ps := httprouter.Params{httprouter.Param{
		Key:   "filename",
		Value: "dummy",
	}}

	w = httptest.NewRecorder()
	storeFile(w, req, ps)
	assert.Equal(t, 200, w.Code)
}

func TestGetFile(t *testing.T) {
	err := datastore.MakeDB()
	assert.NoError(t, err)
	//Register
	b := bytes.Buffer{}
	b.Write([]byte(`{"username":"user3", "password":"best_password"}`))
	req := mockhttp.NewRequest(t, "POST", "/register", &b)
	w := httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, 204, w.Code)

	//Login OK
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"user3", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/login", &b)
	w = httptest.NewRecorder()
	login(w, req, nil)
	var j jlogin
	err = json.Unmarshal(w.Body.Bytes(), &j)
	assert.NoError(t, err)
	assert.True(t, len(j.Token) > 0)

	data := bytes.Buffer{}
	data.Write([]byte("hello operator, i'm a dummy file"))
	req = mockhttp.NewRequest(t, "POST", "/files/dummy", &data)
	//req.Body = &data
	req.Header.Set("X-Session", j.Token)
	req.Header.Set("Content-Type", "VirtualFile")
	l := strconv.Itoa(data.Len())
	req.Header.Set("Content-Length", l)
	ps := httprouter.Params{httprouter.Param{
		Key:   "filename",
		Value: "dummy",
	}}

	w = httptest.NewRecorder()
	storeFile(w, req, ps)
	assert.Equal(t, 200, w.Code)

	req = mockhttp.NewRequest(t, "POST", "/files/dummy", &data)
	req.Header.Set("X-Session", j.Token)
	w = httptest.NewRecorder()
	getFile(w, req, ps)
	assert.Contains(t, w.Body.String(), "operator")
}

func TestGetAllFiles(t *testing.T) {
	err := datastore.MakeDB()
	assert.NoError(t, err)
	//Register
	b := bytes.Buffer{}
	b.Write([]byte(`{"username":"user3", "password":"best_password"}`))
	req := mockhttp.NewRequest(t, "POST", "/register", &b)
	w := httptest.NewRecorder()
	register(w, req, nil)
	assert.Equal(t, 204, w.Code)

	//Login OK
	b = bytes.Buffer{}
	b.Write([]byte(`{"username":"user3", "password":"best_password"}`))
	req = mockhttp.NewRequest(t, "POST", "/login", &b)
	w = httptest.NewRecorder()
	login(w, req, nil)
	var j jlogin
	err = json.Unmarshal(w.Body.Bytes(), &j)
	assert.NoError(t, err)
	assert.True(t, len(j.Token) > 0)

	data := bytes.Buffer{}
	data.Write([]byte("hello operator, i'm a dummy file"))
	req = mockhttp.NewRequest(t, "POST", "/files/dummy", &data)
	req.Header.Set("X-Session", j.Token)
	req.Header.Set("Content-Type", "VirtualFile")
	l := strconv.Itoa(data.Len())
	req.Header.Set("Content-Length", l)
	ps := httprouter.Params{httprouter.Param{
		Key:   "filename",
		Value: "dummy",
	}}

	w = httptest.NewRecorder()
	storeFile(w, req, ps)

	req = mockhttp.NewRequest(t, "GET", "/files", &data)
	req.Header.Set("X-Session", j.Token)
	getFiles(w, req, nil)
	assert.Contains(t, w.Body.String(), "dummy")
}
