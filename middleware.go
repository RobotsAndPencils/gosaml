package saml

//
// import (
// 	"bytes"
// 	"compress/flate"
// 	"encoding/base64"
// 	"fmt"
// 	"github.com/gorilla/sessions"
// 	"net/http"
// 	"net/url"
// )
//
// type samlAuth struct {
// 	h               http.Handler
// 	c               Config
// 	AppSettings     AppSettings
// 	AccountSettings AccountSettings
// 	store           *sessions.CookieStore
// 	sessionKey      string
// }
//
// type Config struct {
// 	CertificatePath             string
// 	IDP_SSO_Target_URL          string
// 	AssertionConsumerServiceURL string
// 	Issuer                      string
// }
//
// //var store = sessions.NewCookieStore([]byte("something-very-secret"))
//
// func Middleware(c Config, store *sessions.CookieStore, sessionKey string) func(h http.Handler) http.Handler {
// 	fn := func(h http.Handler) http.Handler {
// 		return samlAuth{
// 			h:               h,
// 			c:               c,
// 			AppSettings:     NewAppSettings(c.AssertionConsumerServiceURL, c.Issuer),
// 			AccountSettings: NewAccountSettings(c.CertificatePath, c.IDP_SSO_Target_URL),
// 			store:           store,
// 			sessionKey:      sessionKey,
// 		}
// 	}
// 	return fn
// }
//
// func (s samlAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	session, err := s.store.Get(r, s.sessionKey)
// 	fmt.Println(r.URL.Path)
// 	fmt.Println(r.Method)
// 	if err != nil {
// 		fmt.Println("No Session")
// 	}
//
// 	if r.URL.Path == "/auth" && r.Method == "POST" {
// 		//Request coming back from IDP
// 		r.ParseForm()
// 		samlResp := r.PostFormValue("SAMLResponse")
// 		x, err := Parse(samlResp, &s.AppSettings, &s.AccountSettings)
// 		//fmt.Println(err)
// 		//fmt.Println(x)
// 		//fmt.Fprintf(w, "%s", x)
// 		if err != nil {
// 			fmt.Println("SAML Parse Error")
// 		}
//
// 		session, _ := s.store.Get(r, s.sessionKey)
// 		for k, v := range x {
// 			session.Values[k] = v
// 		}
// 		session.Save(r, w)
//
// 		s.h.ServeHTTP(w, r)
// 	} else if _, ok := session.Values["userID"]; ok {
// 		//Has a session, pass them back
// 		s.h.ServeHTTP(w, r)
// 	} else {
// 		//No session make saml request
//
// 		// Construct an AuthnRequest
// 		authRequest := NewAuthorizationRequest(s.AppSettings, s.AccountSettings)
//
// 		// Return a SAML AuthnRequest as a string
// 		samlRequest, err := authRequest.GetRequest(false)
//
// 		if err != nil {
// 			fmt.Println(err)
// 			return
// 		}
//
// 		var b bytes.Buffer
// 		wr, _ := flate.NewWriter(&b, flate.DefaultCompression)
// 		wr.Write([]byte(samlRequest))
// 		wr.Close()
// 		b64 := base64.StdEncoding.EncodeToString(b.Bytes())
// 		q := url.QueryEscape(b64)
// 		fmt.Println(q)
// 		fmt.Println(session.Values)
// 		//h.ServeHTTP(w, r)
//
// 		http.Redirect(w, r, s.c.IDP_SSO_Target_URL+"?SAMLRequest="+q, http.StatusFound)
// 	}
//
// 	//s.h.ServeHTTP(w, r)
// }
