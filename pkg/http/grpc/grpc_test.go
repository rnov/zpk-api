package grpc

import (
	"context"
	"log"
	"testing"
	"time"
	pb "zkp-api/pkg/http/grpc/zkp"
)

func TestConnection(t *testing.T) {

	tests := []struct {
		name string
		req  *pb.RegisterRequest
	}{
		{
			name: "register request",
			req:  &pb.RegisterRequest{User: "Alice", Y1: 123, Y2: 456},
		},
	}

	as := &AuthServer{}
	errS := as.InitServer("tcp", ":50051")
	if errS != nil {
		t.Fatalf("unable to init server: %s", errS.Error())
	}

	ac := &AuthClient{}
	c, errC := ac.InitClient("localhost:50051")
	if errC != nil {
		t.Fatalf("unable to init client: %s", errC.Error())
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, err := c.Register(ctx, test.req)
			if err != nil {
				log.Fatalf("could not register: %v", err)
			}

			log.Printf("Response: %v", r)
		})
	}
}

//
//
//func main() {
//	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithBlock())
//	if err != nil {
//		log.Fatalf("did not connect: %v", err)
//	}
//	defer conn.Close()
//	c := pb.NewAuthClient(conn)
//
//	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
//	defer cancel()
//	r, err := c.Register(ctx, &pb.RegisterRequest{User: "Alice", Y1: 123, Y2: 456})
//	if err != nil {
//		log.Fatalf("could not register: %v", err)
//	}
//	log.Printf("Response: %v", r)
//}
