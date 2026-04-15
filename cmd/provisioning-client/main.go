package main

import (
	"log"
)

func main() {
	if !parseOpts() {
		return
	}

	if opts.BTScan || opts.BTMode {
		if err := btClient(); err != nil {
			log.Println(err)
		}
	} else {
		if err := grpcClient(); err != nil {
			log.Println(err)
		}
	}
}
