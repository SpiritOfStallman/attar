/*
	Attar package provide simple way to get http user auth (via sessions and cookie).

	It use part of great Gorilla web toolkit, 'gorilla/sessions' package
	(http://github.com/gorilla/sessions).

*/
package attar

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

type Attar struct {
	authProviderFunc authProvider
	loginRoute       string
	cookieOptions    *Options
	cookieStore      *sessions.CookieStore
}

/*
	Primary attar options (except for basic settings also accommodates a
	'gorilla/sessions' options (http://www.gorillatoolkit.org/pkg/sessions#Options)).
*/
type Options struct {
	// 'gorilla/sessions' section:
	// description see on http://www.gorillatoolkit.org/pkg/sessions#Options
	// or source on github
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool

	// attar section:
	// name of cookie browser session
	SessionName     string // default: "attar-session"
	SessionLifeTime int    // default: 86400; in sec

	// bind browser useragent to cookie
	SessionBindUseragent bool

	// bind user IP addr to cookie
	SessionBindUserHost bool

	// html field names, to retrieve
	// user name and password from
	// login form
	LoginFormUserFieldName     string // default: "login"
	LoginFormPasswordFieldName string // default: "password"
}

/*
	Set attar options (*Options).
*/
func (a *Attar) Config(o *Options) {
	a.cookieOptions = o
}

/*
	Function for check auth session.
*/
func (a *Attar) GlobalAuthProxy(next http.Handler) http.HandlerFunc {
	// сheck mandatory parameters
	if a.loginRoute == "" {
		log.Fatalf("attar error: login route not declared (SetLoginRoute)")
	}
	if a.authProviderFunc == nil {
		log.Fatalf("attar error: auth provider not declared (SetAuthProvider)")
	}
	return func(res http.ResponseWriter, req *http.Request) {
		if req.URL.Path == a.loginRoute {
			next.ServeHTTP(res, req)
			return
		}

		var cookieStore = a.cookieStore

		cookieStore.Options = &sessions.Options{
			Path:     a.cookieOptions.Path,
			Domain:   a.cookieOptions.Domain,
			MaxAge:   a.cookieOptions.MaxAge,
			Secure:   a.cookieOptions.Secure,
			HttpOnly: a.cookieOptions.HttpOnly,
		}

		session, err := cookieStore.Get(req, a.cookieOptions.SessionName)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		currentTime := time.Now().Local()

		val, ok := session.Values["loginTime"]
		if !ok {
			http.Redirect(res, req, a.loginRoute, http.StatusFound)
			return
		}

		userLoginTime, err := time.Parse(time.RFC3339, val.(string))
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		if int(currentTime.Sub(userLoginTime).Seconds()) > a.cookieOptions.SessionLifeTime {
			http.Redirect(res, req, a.loginRoute, http.StatusFound)
			return
		}

		if a.cookieOptions.SessionBindUseragent {
			val, ok = session.Values["useragent"]
			if !ok {
				http.Redirect(res, req, a.loginRoute, http.StatusFound)
				return
			}

			if req.UserAgent() != val.(string) {
				http.Redirect(res, req, a.loginRoute, http.StatusFound)
				return
			}
		}

		if a.cookieOptions.SessionBindUserHost {
			val, ok = session.Values["userHost"]
			if !ok {
				http.Redirect(res, req, a.loginRoute, http.StatusFound)
				return
			}

			if strings.Split(req.RemoteAddr, ":")[0] != val.(string) {
				http.Redirect(res, req, a.loginRoute, http.StatusFound)
				return
			}
		}

		next.ServeHTTP(res, req)
	}
}

/*
	Logut handler, expire the session and save it.
*/
func (a *Attar) LogoutHandler(res http.ResponseWriter, req *http.Request) {

	cookieStore := a.cookieStore

	session, err := cookieStore.Get(req, a.cookieOptions.SessionName)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Options.MaxAge = -1
	session.Save(req, res)

	http.Redirect(res, req, "/", http.StatusFound)

}

/*
	Auth handler, for grub login form data, and init cookie session.
*/
func (a *Attar) AuthHandler(res http.ResponseWriter, req *http.Request) {
	user := req.FormValue(a.cookieOptions.LoginFormUserFieldName)
	password := req.FormValue(a.cookieOptions.LoginFormPasswordFieldName)
	cookieStore := a.cookieStore

	if !a.authProviderFunc(user, password) {
		http.Redirect(res, req, a.loginRoute, http.StatusFound)
		return
	}

	session, err := cookieStore.Get(req, a.cookieOptions.SessionName)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
	currentTime := time.Now().Local()

	session.Values["user"] = req.FormValue(a.cookieOptions.LoginFormUserFieldName)
	session.Values["loginTime"] = currentTime.Format(time.RFC3339)

	// even if SessionBindUseragent or SessionBindUserHost is false -
	// this data save to cookie, for option change without
	// having to user relogin (and cookie re-get)
	session.Values["userHost"] = strings.Split(req.RemoteAddr, ":")[0]
	session.Values["useragent"] = req.UserAgent()

	session.Save(req, res)

	http.Redirect(res, req, "/", http.StatusFound)
}

/*
	Get path for login redirect.
*/
func (a *Attar) SetLoginRoute(r string) {
	a.loginRoute = r
}

/*
	Set 'gorilla/sessions' session cookie keys.

	Attention! Conflict with attar.SetGorillaCookieStore.

	For more information about NewCookieStore() refer
	to http://www.gorillatoolkit.org/pkg/sessions#NewCookieStore.
*/
func (a *Attar) SetCookieSessionKeys(authKey, encryptionKey []byte) {
	a.cookieStore = sessions.NewCookieStore(
		authKey,
		encryptionKey,
	)
}

/*
	Set pre-define 'gorilla/sessions' CookieStore as attar CookieStore.

	Attention! Conflict with attar.SetCookieSessionKeys.

	Example:
		import (
			"github.com/gorilla/sessions"
			"github.com/SpiritOfStallman/attar"
		)

		func main() {
			..
			gorillaSessions := sessions.NewCookieStore(
				[]byte("261AD9502C583BD7D8AA03083598653B"),
				[]byte("E9F6FDFAC2772D33FC5C7B3D6E4DDAFF"),
			)
			..
			a := attar.New()
			a.SetGorillaCookieStore(gorillaSessions)
			..
		}

*/
func (a *Attar) SetGorillaCookieStore(c *sessions.CookieStore) {
	a.cookieStore = c
}

// type for auth provider function
type authProvider (func(u, p string) bool)

/*
	Method for set "auth provider" function, and user verification.

	User functon must take 'user' and 'password' arguments, and return
	true (if user auth successfully) or false (if auth data false).

	As alternative use preset attar auth provider functions (like
	attar.SimpleAuthProvider)

	Example of auth provider function:
		// user code
		func checkAuth(u, p string) bool {
			if u == "user" && p == "qwerty" {
				return true
			}
			return false
		}

	And define it:
		// user code
		a := attar.New()
		a.SetAuthProvider(checkAuth)
*/
func (a *Attar) SetAuthProvider(f authProvider) {
	a.authProviderFunc = f
}

/*
	User auth provider function, for simple user/password check.

	Example of usage:
		// users list based on map[user]password
		userList := map[string]string{
			"user":  "qwerty",
			"admin": "asdfgh",
		}

		a := attar.New()
		a.SetAuthProvider(a.SimpleAuthProvider(userList))
*/
func (a *Attar) SimpleAuthProvider(userlist map[string]string) authProvider {
	return func(u, p string) bool {
		pass, ok := userlist[u]
		if !ok {
			return false
		}
		if len(p) != len(pass) {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(pass), []byte(p)) != 1 {
			return false
		}
		return true
	}
}

/*
	Return Attar struct with default options.

	By default contain pre-set keys to 'gorilla/sessions' NewCookieStore
	func (provide in *Attar.CookieSessionKeys).
	It is not secure.
	Keys must be changed!

	For more information about NewCookieStore() refer
	to http://www.gorillatoolkit.org/pkg/sessions#NewCookieStore.

*/
func New() *Attar {
	return &Attar{
		// default options
		cookieOptions: &Options{
			SessionName:                "attar-session",
			SessionLifeTime:            86400,
			SessionBindUseragent:       true,
			SessionBindUserHost:        true,
			LoginFormUserFieldName:     "login",
			LoginFormPasswordFieldName: "password",
		},
		// use default keys is not secure! :)
		cookieStore: sessions.NewCookieStore(
			[]byte("261AD9502C583BD7D8AA03083598653B"),
			[]byte("E9F6FDFAC2772D33FC5C7B3D6E4DDAFF"),
		),
	}
}
