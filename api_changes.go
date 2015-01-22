package attar

import (
	"log"
)

func printDeprecatedApiMessage(fn, ff string) {
	hm := "Attar package error!"
	dam := "Please, udate code according to API changes."
	log.Fatalf("%s\nFucntion %s deprecated.\n%s\n%s\n", hm, fn, dam, ff)
}

type AttarOptions struct {
	Path                       string
	Domain                     string
	MaxAge                     int
	Secure                     bool
	HttpOnly                   bool
	SessionName                string
	SessionLifeTime            int
	SessionBindUseragent       bool
	SessionBindUserHost        bool
	LoginFormUserFieldName     string
	LoginFormPasswordFieldName string
}

func (a *Attar) SetAttarOptions(o *AttarOptions) {
	funcName := "SetAttarOptions"
	funcFix := "Need to change the func name from 'SetAttarOptions' to 'Config', and config struct name from 'AttarOptions' to 'Options'"
	printDeprecatedApiMessage(funcName, funcFix)
}
