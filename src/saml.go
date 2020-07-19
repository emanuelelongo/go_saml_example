package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/sessions"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

type samlOptions struct {
	TenantID             string
	AppID                string
	AppIDURI             string
	CallbackURL          string
	OnLoginRedirectPath  string
	OnLogoutRedirectPath string
	CookieName           string
	CookieSecret         string
}

type samlOutput struct {
	CallbackHandler func(w http.ResponseWriter, r *http.Request)
	AuthURL         string
	CheckAuth       func(r *http.Request) (*userInfo, error)
	WithAuth        func(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request)
	Logout          func(w http.ResponseWriter, r *http.Request)
}

type userInfo struct {
	Name    string `json:"name"`
	Surname string `json:"surname"`
	NameID  string `json:"id"`
	Email   string `json:"email"`
}

func samlInit(options samlOptions) (samlOutput, error) {
	gob.Register(userInfo{})
	var store = sessions.NewCookieStore([]byte(options.CookieSecret))

	metadataURL := fmt.Sprintf("https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml?appid=%s", options.TenantID, options.AppID)
	res, err := http.Get(metadataURL)
	if err != nil {
		return samlOutput{}, err
	}

	rawMetadata, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlOutput{}, err
	}

	metadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		return samlOutput{}, err
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				return samlOutput{}, fmt.Errorf("metadata certificate(%d) must not be empty", idx)
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				return samlOutput{}, err
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return samlOutput{}, err
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       options.AppIDURI,
		AssertionConsumerServiceURL: options.CallbackURL,
		SignAuthnRequests:           false,
		AudienceURI:                 options.AppIDURI,
		IDPCertificateStore:         &certStore,
	}
	authURL, err := sp.BuildAuthURL("")
	if err != nil {
		return samlOutput{}, err
	}

	callbackHandler := func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		assertionInfo, err := sp.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		session, _ := store.Get(r, options.CookieName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user := &userInfo{
			Name:    assertionInfo.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"),
			Surname: assertionInfo.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"),
			Email:   assertionInfo.Values.Get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
			NameID:  assertionInfo.NameID,
		}
		session.Values["user"] = user
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, options.OnLoginRedirectPath, 302)
	}

	checkAuth := func(r *http.Request) (*userInfo, error) {
		session, err := store.Get(r, options.CookieName)
		if err != nil {
			return nil, err
		}

		if session.Values["user"] != nil {
			user := session.Values["user"].(userInfo)
			return &user, nil
		}
		return nil, nil
	}

	withAuth := func(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			user, err := checkAuth(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			handler(w, r)
		}
	}

	logout := func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, options.CookieName)
		session.Values["user"] = nil
		err = session.Save(r, w)
		http.Redirect(w, r, options.OnLogoutRedirectPath, 302)
	}

	return samlOutput{
		CallbackHandler: callbackHandler,
		AuthURL:         authURL,
		CheckAuth:       checkAuth,
		WithAuth:        withAuth,
		Logout:          logout,
	}, nil
}
