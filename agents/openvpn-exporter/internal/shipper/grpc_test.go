package shipper

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type testSessionServiceServer interface {
	ReportSnapshot(context.Context, *structpb.Struct) (*emptypb.Empty, error)
}

type testServer struct {
	received chan *structpb.Struct
}

func (s *testServer) ReportSnapshot(_ context.Context, in *structpb.Struct) (*emptypb.Empty, error) {
	s.received <- in
	return &emptypb.Empty{}, nil
}

func registerTestSessionService(s *grpc.Server, impl testSessionServiceServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "openvpn.v1.SessionService",
		HandlerType: (*testSessionServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "ReportSnapshot",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					in := new(structpb.Struct)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return srv.(testSessionServiceServer).ReportSnapshot(ctx, in)
					}
					info := &grpc.UnaryServerInfo{
						Server:     srv,
						FullMethod: "/openvpn.v1.SessionService/ReportSnapshot",
					}
					handler := func(ctx context.Context, req interface{}) (interface{}, error) {
						return srv.(testSessionServiceServer).ReportSnapshot(ctx, req.(*structpb.Struct))
					}
					return interceptor(ctx, in, info, handler)
				},
			},
		},
	}, impl)
}

func TestClient_SendMap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	received := make(chan *structpb.Struct, 1)
	srv := grpc.NewServer()
	registerTestSessionService(srv, &testServer{received: received})
	defer srv.Stop()

	go func() {
		_ = srv.Serve(ln)
	}()

	cli := &Client{
		Target:     ln.Addr().String(),
		MethodName: "/openvpn.v1.SessionService/ReportSnapshot",
		Timeout:    2 * time.Second,
	}

	if err := cli.Connect(); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer func() { _ = cli.Close() }()

	payload := map[string]any{
		"active_client_count": int64(2),
		"collector_source":    "openvpn-management-interface",
	}
	if err := cli.SendMap(context.Background(), payload); err != nil {
		t.Fatalf("send map failed: %v", err)
	}

	select {
	case got := <-received:
		if got.Fields["collector_source"].GetStringValue() != "openvpn-management-interface" {
			t.Fatalf("unexpected collector_source: %v", got.Fields["collector_source"])
		}
		if got.Fields["active_client_count"].GetNumberValue() != 2 {
			t.Fatalf("unexpected active_client_count: %v", got.Fields["active_client_count"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for gRPC payload")
	}
}

func TestClient_SendMap_NotConnected(t *testing.T) {
	cli := &Client{
		Target:     "127.0.0.1:50051",
		MethodName: "/openvpn.v1.SessionService/ReportSnapshot",
		Timeout:    time.Second,
	}

	err := cli.SendMap(context.Background(), map[string]any{"x": "y"})
	if err == nil {
		t.Fatal("expected error when client is not connected")
	}
}
