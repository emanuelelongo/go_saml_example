package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"html/template"
)

type homePageData struct {
	AuthURL string
	User    string
}

func main() {
	opt := samlOptions{
		TenantID:             os.Getenv("TENANT_ID"),
		AppID:                os.Getenv("APP_ID"),
		AppIDURI:             os.Getenv("APP_ID_URI"),
		CallbackURL:          "https://localhost:9090/callback",
		OnLoginRedirectPath:  "/",
		OnLogoutRedirectPath: "/",
		CookieName:           "token",
		CookieSecret:         "This is secret, look elsewhere!",
	}

	saml, _ := samlInit(opt)
	homePage := template.Must(template.ParseFiles("src/templates/home.html"))
	privatePage := template.Must(template.ParseFiles("src/templates/private.html"))

	http.HandleFunc("/callback", saml.CallbackHandler)
	http.HandleFunc("/logout", saml.Logout)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user, _ := saml.CheckAuth(r)

		data := homePageData{
			User:    user,
			AuthURL: saml.AuthURL,
		}
		homePage.Execute(w, data)
	})

	http.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		user, _ := saml.CheckAuth(r)
		if user == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		privatePage.Execute(w, nil)
	})

	fmt.Println("Listening on port 9090")
	log.Fatal(http.ListenAndServeTLS(":9090", "src/cert/localhost.cert", "src/cert/localhost.key", nil))
}
