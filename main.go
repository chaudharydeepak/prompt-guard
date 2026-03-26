package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	"github.com/chaudharydeepak/prompt-guard/proxy"
	"github.com/chaudharydeepak/prompt-guard/store"
	"github.com/chaudharydeepak/prompt-guard/web"
)

func main() {
	port    := flag.Int("port", 8080, "Proxy port")
	webPort := flag.Int("web-port", 7778, "Web dashboard port")
	caDir   := flag.String("ca-dir", defaultCADir(), "Directory for CA cert/key and database")
	flag.Parse()

	if err := os.MkdirAll(*caDir, 0700); err != nil {
		log.Fatalf("mkdir %s: %v", *caDir, err)
	}

	db, err := store.Open(filepath.Join(*caDir, "prompt-guard.db"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	ca, err := proxy.LoadOrCreateCA(*caDir)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}

	eng := inspector.New()

	printSetup(ca.CertPath, *port, *webPort)
	web.Start(*webPort, db, eng)
	log.Fatal(proxy.Start(*port, ca, db, eng))
}

func defaultCADir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".prompt-guard")
}

func printSetup(certPath string, port, webPort int) {
	fmt.Println("\n┌─────────────────────────────────────────┐")
	fmt.Println("│           Prompt Guard starting         │")
	fmt.Println("└─────────────────────────────────────────┘")
	fmt.Printf("\nCA cert:   %s\n\n", certPath)

	switch runtime.GOOS {
	case "darwin":
		fmt.Printf("Install CA (run once):\n  sudo security add-trusted-cert -d -r trustRoot \\\n    -k /Library/Keychains/System.keychain %s\n\n", certPath)
	case "linux":
		fmt.Printf("Install CA (run once):\n  sudo cp %s /usr/local/share/ca-certificates/prompt-guard.crt\n  sudo update-ca-certificates\n\n", certPath)
	case "windows":
		fmt.Printf("Install CA (run once):\n  certutil -addstore -f ROOT %s\n\n", certPath)
	}

	fmt.Printf("Set proxy:\n  export HTTP_PROXY=http://localhost:%d\n  export HTTPS_PROXY=http://localhost:%d\n  export NO_PROXY=localhost,127.0.0.1\n\n", port, port)
	fmt.Printf("Dashboard: http://localhost:%d\n\n", webPort)
}
