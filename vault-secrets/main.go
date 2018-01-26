package main

import (
	"fmt"
	"log"
	"os"

	vault "github.com/hashicorp/vault/api"
)

// Logical vault
type VaultLogical struct {
	path   string
	Client *vault.Client
	Config *vault.Config
}

func (v *VaultLogical) readPath(key, path string) (interface{}, error) {
	s, err := v.Client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("err: %s", err)
	}
	secretVal := s.Data[key]
	return secretVal, nil
}

func newVaultClient(vaultToken string) (*VaultLogical, error) {
	vConfig := vault.DefaultConfig()
	vClient, err := vault.NewClient(vConfig)
	if err != nil {
		return nil, fmt.Errorf("err: %s", err)
	}
	vClient.SetToken(vaultToken)
	vl := &VaultLogical{
		Client: vClient,
		Config: vConfig,
	}
	return vl, nil
}

func main() {
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		log.Fatal("VAULT_TOKEN env variable is empty")
	}
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		log.Fatal("VAULT_ADDR env variable is empty")
	}
	vaultClient, err := newVaultClient(vaultToken)
	if err != nil {
		log.Fatalf("err: %s\n", err)
	}
	helloSecret, err := vaultClient.readPath("hello", "secret/foo")
	if err != nil {
		log.Fatalf("err: %+s\n", err)
	}
	log.Printf("hello = %+v\n", helloSecret)

	// log.Println("writing to secret/foo hello=world")
	// s := make(map[string]interface{})
	// s["hello"] = 123
	// secret, err = client.Logical().Write("secret/foo", s)
	// if err != nil {
	// 	log.Fatalf("err: %+v\n", err)
	// }

}
