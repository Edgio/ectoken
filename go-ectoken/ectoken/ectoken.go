package main

import (
	"fmt"
	"os"

	"github.com/VerizonDigital/ectoken/go-ectoken"
)

var usage = `Usage:
 To Encrypt:
     ec_encrypt <key> <text>
 or:
     ec_encrypt encrypt <key> <text>
 To Decrypt:
     ec_encrypt decrypt <key> <text>
`

func main() {
	var (
		action string = "encrypt"
		key    string
		token  string
	)
	switch len(os.Args) {
	case 3:
		key, token = os.Args[1], os.Args[2]
	case 4:
		action, key, token = os.Args[1], os.Args[2], os.Args[3]
	default:
		fmt.Println("error: wrong number of arguments specified")
		fmt.Print(usage)
		os.Exit(-1)
	}

	switch action {
	case "encrypt":
		fmt.Println(ectoken.EncryptV3(key, token))
	case "decrypt":
		out, err := ectoken.DecryptV3(key, token)
		if err != nil {
			fmt.Printf("error: %s\n", err)
			os.Exit(-1)
		}
		fmt.Println(out)
	default:
		fmt.Printf("error: unrecognized action type %s ", action)
		fmt.Println(usage)
		os.Exit(0)
	}
}
