// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.4
// source: drand/api.proto

package drand

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// PublicClient is the client API for Public service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PublicClient interface {
	// PublicRand is the method that returns the publicly verifiable randomness
	// generated by the drand network.
	PublicRand(ctx context.Context, in *PublicRandRequest, opts ...grpc.CallOption) (*PublicRandResponse, error)
	PublicRandStream(ctx context.Context, in *PublicRandRequest, opts ...grpc.CallOption) (Public_PublicRandStreamClient, error)
	// ChainInfo returns the information related to the chain this node
	// participates to
	ChainInfo(ctx context.Context, in *ChainInfoRequest, opts ...grpc.CallOption) (*ChainInfoPacket, error)
	// Home is a simple endpoint
	Home(ctx context.Context, in *HomeRequest, opts ...grpc.CallOption) (*HomeResponse, error)
}

type publicClient struct {
	cc grpc.ClientConnInterface
}

func NewPublicClient(cc grpc.ClientConnInterface) PublicClient {
	return &publicClient{cc}
}

func (c *publicClient) PublicRand(ctx context.Context, in *PublicRandRequest, opts ...grpc.CallOption) (*PublicRandResponse, error) {
	out := new(PublicRandResponse)
	err := c.cc.Invoke(ctx, "/drand.Public/PublicRand", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *publicClient) PublicRandStream(ctx context.Context, in *PublicRandRequest, opts ...grpc.CallOption) (Public_PublicRandStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &Public_ServiceDesc.Streams[0], "/drand.Public/PublicRandStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &publicPublicRandStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Public_PublicRandStreamClient interface {
	Recv() (*PublicRandResponse, error)
	grpc.ClientStream
}

type publicPublicRandStreamClient struct {
	grpc.ClientStream
}

func (x *publicPublicRandStreamClient) Recv() (*PublicRandResponse, error) {
	m := new(PublicRandResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *publicClient) ChainInfo(ctx context.Context, in *ChainInfoRequest, opts ...grpc.CallOption) (*ChainInfoPacket, error) {
	out := new(ChainInfoPacket)
	err := c.cc.Invoke(ctx, "/drand.Public/ChainInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *publicClient) Home(ctx context.Context, in *HomeRequest, opts ...grpc.CallOption) (*HomeResponse, error) {
	out := new(HomeResponse)
	err := c.cc.Invoke(ctx, "/drand.Public/Home", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PublicServer is the server API for Public service.
// All implementations should embed UnimplementedPublicServer
// for forward compatibility
type PublicServer interface {
	// PublicRand is the method that returns the publicly verifiable randomness
	// generated by the drand network.
	PublicRand(context.Context, *PublicRandRequest) (*PublicRandResponse, error)
	PublicRandStream(*PublicRandRequest, Public_PublicRandStreamServer) error
	// ChainInfo returns the information related to the chain this node
	// participates to
	ChainInfo(context.Context, *ChainInfoRequest) (*ChainInfoPacket, error)
	// Home is a simple endpoint
	Home(context.Context, *HomeRequest) (*HomeResponse, error)
}

// UnimplementedPublicServer should be embedded to have forward compatible implementations.
type UnimplementedPublicServer struct {
}

func (UnimplementedPublicServer) PublicRand(context.Context, *PublicRandRequest) (*PublicRandResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PublicRand not implemented")
}
func (UnimplementedPublicServer) PublicRandStream(*PublicRandRequest, Public_PublicRandStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method PublicRandStream not implemented")
}
func (UnimplementedPublicServer) ChainInfo(context.Context, *ChainInfoRequest) (*ChainInfoPacket, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChainInfo not implemented")
}
func (UnimplementedPublicServer) Home(context.Context, *HomeRequest) (*HomeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Home not implemented")
}

// UnsafePublicServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PublicServer will
// result in compilation errors.
type UnsafePublicServer interface {
	mustEmbedUnimplementedPublicServer()
}

func RegisterPublicServer(s grpc.ServiceRegistrar, srv PublicServer) {
	s.RegisterService(&Public_ServiceDesc, srv)
}

func _Public_PublicRand_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PublicRandRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PublicServer).PublicRand(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/drand.Public/PublicRand",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PublicServer).PublicRand(ctx, req.(*PublicRandRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Public_PublicRandStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(PublicRandRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(PublicServer).PublicRandStream(m, &publicPublicRandStreamServer{stream})
}

type Public_PublicRandStreamServer interface {
	Send(*PublicRandResponse) error
	grpc.ServerStream
}

type publicPublicRandStreamServer struct {
	grpc.ServerStream
}

func (x *publicPublicRandStreamServer) Send(m *PublicRandResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _Public_ChainInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChainInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PublicServer).ChainInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/drand.Public/ChainInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PublicServer).ChainInfo(ctx, req.(*ChainInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Public_Home_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HomeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PublicServer).Home(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/drand.Public/Home",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PublicServer).Home(ctx, req.(*HomeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Public_ServiceDesc is the grpc.ServiceDesc for Public service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Public_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "drand.Public",
	HandlerType: (*PublicServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PublicRand",
			Handler:    _Public_PublicRand_Handler,
		},
		{
			MethodName: "ChainInfo",
			Handler:    _Public_ChainInfo_Handler,
		},
		{
			MethodName: "Home",
			Handler:    _Public_Home_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "PublicRandStream",
			Handler:       _Public_PublicRandStream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "drand/api.proto",
}
