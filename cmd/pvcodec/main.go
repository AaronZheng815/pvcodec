package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AaronZheng815/pvcodec/internal/httpapi"
)

func main() {
	port := flag.Int("port", 8080, "server listen port")
	webDir := flag.String("web", "web/dist", "frontend static files directory")
	flag.Parse()

	srv := httpapi.NewServer(*webDir)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("pvcodec listening on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
