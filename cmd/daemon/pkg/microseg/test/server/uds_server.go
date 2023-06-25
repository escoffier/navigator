package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	os.Remove("/tmp/echo.socket")
	// Create a Unix domain socket and listen for incoming connections.
	socket, err := net.Listen("unix", "/tmp/echo.socket")
	if err != nil {
		log.Fatal(err)
	}

	// Cleanup the sockfile.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Remove("/tmp/echo.socket")
		os.Exit(1)
	}()

	for {
		// Accept an incoming connection.
		conn, err := socket.Accept()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("accept new conn")
		// Handle the connection in a separate goroutine.
		go func(conn net.Conn) {
			defer conn.Close()
			// Create a buffer for incoming data.
			buf := make([]byte, 4096)

			// Read data from the connection.
			_, err := conn.Read(buf)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("rev: %s\n", string(buf))
			time.Sleep(time.Second * 3)

			// Echo the data back to the connection.
			response := []byte(`{"status": 100}`)
			_, err = conn.Write([]byte(response))
			if err != nil {
				log.Fatal(err)
			}
		}(conn)
	}
}
