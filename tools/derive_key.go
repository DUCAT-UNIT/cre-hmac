package main

import (
	"fmt"
	"os"
	"ducat/crypto"
)

func main() {
	privKey := os.Getenv("DUCAT_PRIVATE_KEY")
	if privKey == "" {
		fmt.Println("Error: DUCAT_PRIVATE_KEY environment variable not set")
		fmt.Println("\nUsage:")
		fmt.Println("  export DUCAT_PRIVATE_KEY=\"your_64_char_hex_key\"")
		fmt.Println("  go run derive_key.go")
		os.Exit(1)
	}

	kd, err := crypto.DeriveKeys(privKey)
	if err != nil {
		fmt.Printf("Error deriving keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("╔════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║               DUCAT PUBLIC KEY DERIVATION                          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Private Key:  %s\n", privKey)
	fmt.Printf("Public Key:   %s\n", kd.SchnorrPubkey)
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println("  1. Add this public key to ../strfry/strfry.conf:")
	fmt.Println("     whitelistedPubkeys = \"" + kd.SchnorrPubkey + "\"")
	fmt.Println()
	fmt.Println("  2. Restart strfry:")
	fmt.Println("     cd ../strfry && docker-compose restart")
	fmt.Println()
}
