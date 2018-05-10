package main

import (
    "encoding/json"
    "errors"
    "net/http"
    "strconv"
    "time"
    "github.com/gorilla/mux"
    "github.com/dgrijalva/jwt-go"
    log "github.com/cihub/seelog"
)

func InitLogger() {
    logger, err := log.LoggerFromConfigAsFile("seelog.xml")
        
    if err != nil {
        log.Error(err)
    }
        
    log.ReplaceLogger(logger)
}

const (
    codeSuccess = 0
    codeEmptyName = 2
    codeEmptyEmail = 3
    codeEmptyPassword = 4

    codeOops = 14
    codeTodo = 15
    codeFormError = 16
    codeHashError = 17
    codeJwtError = 18

    codeCantOpenDatabase = 22
    codeBadQuery = 23
    codeBadUuid = 24
    codeCantCloseDatabase = 25

    codeEmailAlreadyExists = 30
    codeNoEmailFound = 31
    codePasswordNotMatch = 32

    secretKey = "verysecret"

)


// type User struct {
//     id int `json:"uuid"`
//     firstname string `json:"firstname"`
//     lastname string `json:"lastname"`
//     email string `json:"email"`
//     password string `json:"password"`
//     createdAt string`json:"created_at"`
//     lastLoginAt string `json:"last_login_at"`
//     updatedAt string `json:"updated_at"`
//     isAdmin bool `json:"is_admin"`
// }

// type Message struct {
//     code int `json:"code"`
//     result
// }

// type result struct {
//     User
// }

// fake storage containing a collection of users 
var users []map[string]interface{}

func GetUsers() []map[string]interface{} {
    return users
}

func GenerateId() int {
    return len(users) + 1

}

func IsValidUser(newUser map[string]interface{}) int {
    switch {
    case newUser["firstname"] == "":
        return codeEmptyName
    case newUser["lastname"] == "":
        return codeEmptyName
    case newUser["email"] == "":
        return codeEmptyEmail
    case newUser["password"] == "":
        return codeEmptyPassword
    default:
        return codeSuccess
    }
}

func FindUserByEmail(email string) (map[string]interface{}, error) {
    for _, user := range users {
        if user["email"] == email  {
            return user, nil
        }
    }
    emptyUser := make(map[string]interface{})
    return  emptyUser, errors.New("User not found.")
}

func SendResponse(w http.ResponseWriter, statusCode int, msg map[string]interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Credentials", "true")
    w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Accept, Accept-Language, Content-Type, Origin, token")
    w.Header().Set("Vary", "Origin")
    w.Header().Set("Vary", "Access-Control-Request-Method")
    w.Header().Set("Vary", "Access-Control-Request-Headers")
    w.WriteHeader(statusCode)
    _ = json.NewEncoder(w).Encode(msg)
}

func GetUser(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()

    userId := r.FormValue("userId")
    id, err := strconv.Atoi(userId) 

    if err != nil {
        msg := map[string]interface{}{"code": codeOops, "result": "failure"}
        SendResponse(w, http.StatusInternalServerError, msg)
        return
    }

    if id >= len(users) {
        msg := map[string]interface{}{"code": codeBadUuid, "result": "failure"}
        SendResponse(w, http.StatusNotFound, msg)
        return
    }
    
    user := users[id]
    msg := map[string]interface{}{"code": codeSuccess, "result": user}
    SendResponse(w, http.StatusAccepted, msg)

}


func CreateUser(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    
    newId := GenerateId()
    newUser := map[string]interface{}{
        "id": newId, 
        "firstname": r.FormValue("first_name"), 
        "lastname": r.FormValue("last_name"), 
        "email": r.FormValue("email"), 
        "password": r.FormValue("password")}
    code := IsValidUser(newUser)
    if code != codeSuccess {
        msg := map[string]interface{}{"code": code, "result": "failure"}
        SendResponse(w, http.StatusNotAcceptable, msg)
        return
    }
    now := time.Now()
    newUser["createdAt"] = now.Format(time.RFC3339)
    newUser["isAdmin"] = true

    log.Info("New user created:", newUser)
        
    users = append(users, newUser)

    msg := map[string]interface{}{"code": code, "result": "success"}
    SendResponse(w, http.StatusCreated, msg)

}

func GenerateToken() (string, error) {
    token := jwt.New(jwt.SigningMethodHS256)
    claims := make(jwt.MapClaims)
    claims["admin"] = true
    claims["exp"] = time.Now().Add(time.Hour * 12).Unix()
    token.Claims = claims
    return token.SignedString([]byte(secretKey))
}

func Login(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()

    user, err := FindUserByEmail(r.FormValue("email"))

    if err != nil {
        msg := map[string]interface{}{"code": codeNoEmailFound, "result": "failure"}
        SendResponse(w, http.StatusBadRequest, msg)
        log.Error("Email not found.")
        return
    }
    if user["password"] != r.FormValue("password") {
        msg := map[string]interface{}{"code": codePasswordNotMatch, "result": "failure"}
        SendResponse(w, http.StatusBadRequest, msg)
        log.Error("User password did not match existing one.")
        return
    }

    token, err := GenerateToken()
    if err != nil {
        msg := map[string]interface{}{"code": codeOops, "result": "failure"}
        SendResponse(w, http.StatusInternalServerError, msg)
    }
    log.Info("Token generated: ", token)

    result := map[string]interface{}{"user": user, "token": token}
    msg := map[string]interface{}{"code": codeSuccess, "result": result}
    SendResponse(w, http.StatusAccepted, msg)

}

func main() {
    InitLogger()

    router := mux.NewRouter()

    router.HandleFunc("/users/{id}", GetUser).Methods("OPTIONS")
    router.HandleFunc("/register", CreateUser).Methods("POST")
    router.HandleFunc("/login", Login).Methods("POST")

    log.Debug("Server running at localhost:8080")
    log.Critical(http.ListenAndServe("localhost:8080", router))
}
