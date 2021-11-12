package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", Fibonacci)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func Fibonacci(_ http.ResponseWriter, _ *http.Request) {
	n := 100
	result := make([]uint64, n)
	result[0] = 1
	result[1] = 2
	for i := 2; i < len(result); i++ {
		result[i] = result[i-1] + result[i-2]
	}

	log.Printf("sequence:%+v", result)
}
