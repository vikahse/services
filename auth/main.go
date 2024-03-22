package main

import (
	"crypto/md5"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
)

type UsernamePassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthHandlers struct {
	passwords  map[string][16]byte
	jwtPrivate *rsa.PrivateKey
	jwtPublic  *rsa.PublicKey
}

func NewAuthHandlers(jwtprivateFile string, jwtPublicFile string) *AuthHandlers {
	private, err := os.ReadFile(jwtprivateFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	public, err := os.ReadFile(jwtPublicFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	jwtPrivate, err := jwt.ParseRSAPrivateKeyFromPEM(private)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	jwtPublic, err := jwt.ParseRSAPublicKeyFromPEM(public)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return &AuthHandlers{
		passwords:  make(map[string][16]byte),
		jwtPrivate: jwtPrivate,
		jwtPublic:  jwtPublic,
	}
}

func (h *AuthHandlers) signup(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "signup can be done only with POST HTTP method")
		return
	}
	body := make([]byte, req.ContentLength)
	read, err := req.Body.Read(body)
	defer req.Body.Close()
	if read != int(req.ContentLength) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != io.EOF {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error reading body: %v", err)
		return
	}
	creds := UsernamePassword{}
	err = json.Unmarshal(body, &creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error unmarshalling body: %v", err)
		return
	}
	//check if exists
	_, userExists := h.passwords[creds.Username]
	if userExists {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Уже существует пользователь с таким именем")
		return
	}

	//register user
	hash := md5.Sum([]byte(creds.Password + creds.Username))
	h.passwords[creds.Username] = hash

	//generate jwt token

	token := jwt.New(jwt.GetSigningMethod("RS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = creds.Username
	tokenStr, err := token.SignedString(h.jwtPrivate)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// fmt.Println("jwt=", jwt)

	// TODO: register user, check if exists, generate jwt token and cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "jwt",
		Value: tokenStr, // jwt token string
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Пользователь успешно зарегистрирован")
}

func (h *AuthHandlers) login(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "login can be done only with POST HTTP method")
		return
	}
	body := make([]byte, req.ContentLength)
	read, err := req.Body.Read(body)
	defer req.Body.Close()
	if read != int(req.ContentLength) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != io.EOF {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error reading body: %v", err)
		return
	}
	creds := UsernamePassword{}
	err = json.Unmarshal(body, &creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error unmarshalling body: %v", err)
		return
	}

	password, userExists := h.passwords[creds.Username]
	if !userExists {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Пользователя с таким именем не существует")
		return
	}
	hash := md5.Sum([]byte(creds.Password + creds.Username))
	if password == hash {
		token := jwt.New(jwt.GetSigningMethod("RS256"))

		claims := token.Claims.(jwt.MapClaims)
		claims["username"] = creds.Username

		tokenStr, err := token.SignedString(h.jwtPrivate)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "jwt",
			Value: tokenStr, // jwt token string
		})

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Успешная авторизация")
	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Неверный пароль")
		return
	}

	// TODO: check if user exists, check password and generate cookie
}

func (h *AuthHandlers) whoami(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("jwt")
	if err != nil { //пустой
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenString := cookie.Value
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return h.jwtPrivate, nil
	})

	if err != nil && token == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		username := claims["username"].(string)
		_, userExists := h.passwords[username]
		if !userExists {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Write([]byte("Hello, " + username))
		w.WriteHeader(http.StatusOK)
		return
	}

}

func main() {
	privateFile := flag.String("private", "", "path to JWT private key `file`")
	publicFile := flag.String("public", "", "path to JWT public key `file`")
	port := flag.Int("port", 8091, "http server port")
	flag.Parse()

	if port == nil {
		fmt.Fprintln(os.Stderr, "Port is required")
		os.Exit(1)
	}

	if privateFile == nil || *privateFile == "" {
		fmt.Fprintln(os.Stderr, "Please provide a path to JWT private key file")
		os.Exit(1)
	}

	if publicFile == nil || *publicFile == "" {
		fmt.Fprintln(os.Stderr, "Please provide a path to JWT public key file")
		os.Exit(1)
	}

	absoluteprivateFile, err := filepath.Abs(*privateFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	absolutePublicFile, err := filepath.Abs(*publicFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	authHandlers := NewAuthHandlers(absoluteprivateFile, absolutePublicFile)

	http.HandleFunc("/signup", authHandlers.signup)
	http.HandleFunc("/login", authHandlers.login)
	http.HandleFunc("/whoami", authHandlers.whoami)

	fmt.Println("Starting server on port", *port, "with jwt private key file", absoluteprivateFile, "and jwt public key file", absolutePublicFile)

	if err = http.ListenAndServe(fmt.Sprintf(":%d", *port), nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
