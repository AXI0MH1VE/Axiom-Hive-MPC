package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// unarySecurityInterceptor enforces signature, lattice, and audit hooks on unary RPCs.
func unarySecurityInterceptor(lattice *MotionLattice) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		md, _ := metadata.FromIncomingContext(ctx)

		// 1) Enforce deterministic lattice: ingress -> validate
		if err := lattice.ValidateTransition("ingress", "validate"); err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "%v", err)
		}

		// 2) Check cryptographic session signature header
		if !validSignature(md) {
			return nil, status.Error(codes.PermissionDenied, "missing or invalid x-axiom-signature")
		}

		// 3) Advance lattice to authorize, then route
		if err := lattice.ValidateTransition("validate", "authorize"); err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "%v", err)
		}
		if err := lattice.ValidateTransition("authorize", "route"); err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "%v", err)
		}

		// 4) Call handler
		resp, err := handler(ctx, req)
		if err != nil {
			return nil, err
		}

		// 5) Log state completion transition
		if err := lattice.ValidateTransition("route", "complete"); err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "%v", err)
		}

		return resp, nil
	}
}

// streamSecurityInterceptor mirrors unary but for streams.
func streamSecurityInterceptor(lattice *MotionLattice) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		md, _ := metadata.FromIncomingContext(ss.Context())

		if err := lattice.ValidateTransition("ingress", "validate"); err != nil {
			return status.Errorf(codes.PermissionDenied, "%v", err)
		}
		if !validSignature(md) {
			return status.Error(codes.PermissionDenied, "missing or invalid x-axiom-signature")
		}
		if err := lattice.ValidateTransition("validate", "authorize"); err != nil {
			return status.Errorf(codes.PermissionDenied, "%v", err)
		}
		if err := lattice.ValidateTransition("authorize", "route"); err != nil {
			return status.Errorf(codes.PermissionDenied, "%v", err)
		}

		if err := handler(srv, ss); err != nil {
			return err
		}

		if err := lattice.ValidateTransition("route", "complete"); err != nil {
			return status.Errorf(codes.PermissionDenied, "%v", err)
		}
		return nil
	}
}

// validSignature verifies a deterministic HMAC-style header.
func validSignature(md metadata.MD) bool {
	vals := md.Get("x-axiom-signature")
	if len(vals) == 0 {
		return false
	}
	sig := vals[0]
	// For deterministic demo, derive expected signature from a fixed tag; in production this should use a secret key.
	expected := sha256.Sum256([]byte("axiomhive|sovereign|session"))
	return strings.EqualFold(sig, hex.EncodeToString(expected[:]))
}
