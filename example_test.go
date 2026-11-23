package tcpscanner_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/BarracudaMVP/TCPScanner"
)

func ExampleScanner_Scan() {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)

	scanner, err := tcpscanner.New(tcpscanner.Config{
		Concurrency:    1,
		ConnectTimeout: time.Second,
	})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{address.IP.String()}, tcpscanner.Ports{
		List: []int{address.Port},
	})
	if err != nil {
		panic(err)
	}
	for result := range results {
		fmt.Println(result.State)
	}
	// Output: open
}
