package shipper

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type Client struct {
	Target     string
	MethodName string
	Timeout    time.Duration
	conn       *grpc.ClientConn
}

func (c *Client) Mode() string {
	return "grpc"
}

func (c *Client) Connect() error {
	conn, err := grpc.NewClient(
		c.Target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("dial grpc target: %w", err)
	}
	c.conn = conn
	return nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) SendMap(ctx context.Context, payload map[string]any) error {
	if c.conn == nil {
		return fmt.Errorf("grpc client is not connected")
	}

	msg, err := structpb.NewStruct(payload)
	if err != nil {
		return fmt.Errorf("build protobuf struct: %w", err)
	}

	sendCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	resp := &emptypb.Empty{}
	if err := c.conn.Invoke(sendCtx, c.MethodName, msg, resp); err != nil {
		return fmt.Errorf("invoke grpc method %s: %w", c.MethodName, err)
	}
	return nil
}
