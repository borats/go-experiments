package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nbutton23/zxcvbn-go"
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

var (
	errPasswordReuse     = errors.New("Old password reused")
	errWeakPasswordUsed  = errors.New("Weak password provided")
	errInvalidUser       = errors.New("Invalid User")
	errPasswordDontMatch = errors.New("New passwords do not match")
)

const (
	// TODO use encrypted configuration file
	listenAddress = "0.0.0.0:8081"
	ldapURI       = "ldap.example.org:389" // starttls over :389
	bindDN        = "cn=binduser,dc=example,dc=org"
	bindPW        = "bindpw-p@ssw0rd"
	baseDN        = "dc=example,dc=org"
	searchDN      = "(&(objectClass=organizationalPerson)(uid=%s))"
)

type ldapPasswdUser struct {
	username      string
	currentPasswd string
	newPasswd     string
	ldapUserDN    string
	mu            *sync.Mutex
}

// newLdapPasswdUser set up the ldap request
func newLdapPasswdUser(u, c, n string) *ldapPasswdUser {
	return &ldapPasswdUser{
		username:      u,
		currentPasswd: c,
		newPasswd:     n,
		mu:            &sync.Mutex{},
	}
}

// TODO use html template
func changePasswordHandleFunc(w http.ResponseWriter, req *http.Request) {
	if strings.ToLower(req.Method) == "post" {
		req.ParseForm()
		username := req.Form.Get("username")
		currentPasswd := req.Form.Get("currentpass")
		newPasswd1 := req.Form.Get("newpass1")
		newPasswd := req.Form.Get("newpass2")
		if currentPasswd == newPasswd1 || currentPasswd == newPasswd {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(errPasswordReuse.Error()))
			return
		}
		if newPasswd1 != newPasswd {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(errPasswordDontMatch.Error()))
			return
		}
		// check password strength
		passStrength := zxcvbn.PasswordStrength(newPasswd, nil)
		log.Printf("password provided from: %s for user: %s with a score of: %d\n", req.RemoteAddr, username, passStrength.Score)
		if passStrength.Score < 3 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(errWeakPasswordUsed.Error()))
			return
		}

		log.Printf("initial change password http request received from: %s for user: %s\n", req.RemoteAddr, username)
		ldu := newLdapPasswdUser(username, currentPasswd, newPasswd)
		ok, err := ldu.isValidLDAPUser()
		if err != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(errInvalidUser.Error()))
			return
		}

		if ok {
			err := ldu.changeLdapPasswd()
			if err != nil {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(err.Error()))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Your password has been modified"))
			log.Printf("successfully changed password for user DN: %s from: %s\n", ldu.ldapUserDN, req.RemoteAddr)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`
		<html>
			<head>
				<title>
					Change your LDAP/AD password
				</title>
				<link rel="stylesheet" href="https://netdna.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">
				<link rel="stylesheet" href="https://netdna.bootstrapcdn.com/font-awesome/3.2.1/css/font-awesome.min.css">
			</head>
			<body>
			<form class="form-horizontal" method="post">
			<fieldset>
			
			<!-- Form Name -->
			<legend>Change your LDAP/AD password</legend>
			
			<!-- Text input-->
			<div class="form-group">
			  <label class="col-md-4 control-label" for="textinput">Username</label>  
			  <div class="col-md-4">
			  <input id="textinput" name="username" type="text" placeholder="" class="form-control input-md">				  
			  </div>
			</div>
			
			<!-- Password input-->
			<div class="form-group">
			  <label class="col-md-4 control-label" for="passwordinput">Current password</label>
			  <div class="col-md-4">
				<input id="passwordinput" name="currentpass" type="password" placeholder="" class="form-control input-md">			
			  </div>
			</div>
			
			<!-- Password input-->
			<div class="form-group">
			  <label class="col-md-4 control-label" for="passwordinput">New password</label>
			  <div class="col-md-4">
				<input id="passwordinput" name="newpass1" type="password" placeholder="" class="form-control input-md">			
			  </div>
			</div>
			
			<!-- Password input-->
			<div class="form-group">
			  <label class="col-md-4 control-label" for="passwordinput">New password (again)</label>
			  <div class="col-md-4">
				<input id="passwordinput" name="newpass2" type="password" placeholder="" class="form-control input-md">			
			  </div>
			</div>
			
			<!-- Button -->
			<div class="form-group">
			  <label class="col-md-4 control-label" for="singlebutton"></label>
			  <div class="col-md-4">
				<button id="singlebutton" name="singlebutton" class="btn btn-primary">Update my password</button>
			  </div>
			</div>
			
			</fieldset>
			</form>
			
			</body>
		</html>	
		`))

}

func (ldu *ldapPasswdUser) bootstrapLdapClient() (*ldap.Conn, error) {
	ld, err := ldap.Dial("tcp", ldapURI)
	if err != nil {
		return nil, err
	}

	// TODO use a proper tls.Config object with appropriate certificates for ldap tls
	// `InsecureSkipVerify` should not be set to true in production.
	err = ld.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}

	err = ld.Bind(bindDN, bindPW)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to bind with ldap")
	}
	//ld.Debug = true
	return ld, nil
}

func (ldu *ldapPasswdUser) isValidLDAPUser() (bool, error) {
	ld, err := ldu.bootstrapLdapClient()
	if err != nil {
		return false, err
	}
	defer ld.Close()
	// Search for the given username
	ldapSearchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(searchDN, ldu.username),
		[]string{"dn"},
		nil,
	)
	result, err := ld.Search(ldapSearchReq)
	if err != nil {
		return false, errors.Wrapf(err, "error occurred when searching")
	}

	if len(result.Entries) != 1 {
		return false, errInvalidUser
	}
	userDN := result.Entries[0].DN
	// Bind as the user to verify their password
	err = ld.Bind(userDN, ldu.currentPasswd)
	if err != nil {
		return false, errors.Wrapf(err, "invalid user")
	}

	// Rebind as the read only user for any further queries
	err = ld.Bind(bindDN, bindPW)
	if err != nil {
		return false, err
	}
	if len(userDN) > 0 {
		ldu.ldapUserDN = userDN
		return true, nil
	}
	return false, errInvalidUser
}

func (ldu *ldapPasswdUser) changeLdapPasswd() error {
	ldu.mu.Lock()
	defer ldu.mu.Unlock()
	ld, err := ldu.bootstrapLdapClient()
	if err != nil {
		return err
	}
	defer ld.Close()

	log.Printf("issuing change password request to ldap/ad for user DN: %s\n", ldu.ldapUserDN)
	passModifyReq := ldap.NewPasswordModifyRequest(ldu.ldapUserDN, ldu.currentPasswd, ldu.newPasswd)
	_, err = ld.PasswordModify(passModifyReq)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", changePasswordHandleFunc)
	srv := &http.Server{
		Addr:           listenAddress,
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Printf("running http server at %s\n", listenAddress)
	log.Fatal(srv.ListenAndServe())
}
