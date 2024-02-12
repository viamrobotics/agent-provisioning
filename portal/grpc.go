package portal

import (
	"context"
	"errors"
	"net"
	"time"

	errw "github.com/pkg/errors"
	pb "go.viam.com/api/provisioning/v1"
	"google.golang.org/grpc"

	provisioning "github.com/viamrobotics/agent-provisioning"
)

func (cp *CaptivePortal) startGRPC() error {
	bind := cp.bindAddr + ":4772"
	lis, err := net.Listen("tcp", bind)
	if err != nil {
		return errw.Wrapf(err, "error listening on: %s", bind)
	}

	cp.grpcServer = grpc.NewServer(grpc.WaitForHandlers(true))
	pb.RegisterProvisioningServiceServer(cp.grpcServer, cp)

	cp.workers.Add(1)
	go func() {
		defer cp.workers.Done()
		if err := cp.grpcServer.Serve(lis); err != nil {
			cp.logger.Error(err)
		}
	}()
	return nil
}

func (cp *CaptivePortal) GetSmartMachineStatus(ctx context.Context,
	req *pb.GetSmartMachineStatusRequest,
) (*pb.GetSmartMachineStatusResponse, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.lastInteraction = time.Now()

	ret := &pb.GetSmartMachineStatusResponse{
		ProvisioningInfo: &pb.ProvisioningInfo{
			FragmentId:   cp.factory.FragmentID,
			Model:        cp.factory.Model,
			Manufacturer: cp.factory.Manufacturer,
		},
		HasSmartMachineCredentials: cp.status.deviceConfigured,
		IsOnline:                   cp.status.online,
		LatestConnectionAttempt:    provisioning.NetworkInfoToProto(&cp.status.lastNetwork),
		Errors:                     cp.errListAsStrings(),
	}

	// reset the errors, as they were now just displayed
	cp.status.errors = nil

	return ret, nil
}

func (cp *CaptivePortal) SetNetworkCredentials(ctx context.Context,
	req *pb.SetNetworkCredentialsRequest,
) (*pb.SetNetworkCredentialsResponse, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.lastInteraction = time.Now()

	if req.GetType() != "wifi" {
		return nil, errors.New("unknown network type, only 'wifi' currently supported")
	}

	cp.input.Updated = time.Now()
	cp.input.SSID = req.GetSsid()
	cp.input.PSK = req.GetPsk()
	cp.inputRecieved.Store(true)

	return &pb.SetNetworkCredentialsResponse{}, nil
}

func (cp *CaptivePortal) SetSmartMachineCredentials(ctx context.Context,
	req *pb.SetSmartMachineCredentialsRequest,
) (*pb.SetSmartMachineCredentialsResponse, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.lastInteraction = time.Now()

	cloud := req.GetCloud()
	if cloud == nil {
		return nil, errors.New("request must include a Cloud config section")
	}

	cp.input.Updated = time.Now()
	cp.input.PartID = cloud.GetId()
	cp.input.Secret = cloud.GetSecret()
	cp.input.AppAddr = cloud.GetAppAddress()
	cp.inputRecieved.Store(true)

	return &pb.SetSmartMachineCredentialsResponse{}, nil
}

func (cp *CaptivePortal) GetNetworkList(ctx context.Context,
	req *pb.GetNetworkListRequest,
) (*pb.GetNetworkListResponse, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.lastInteraction = time.Now()

	networks := make([]*pb.NetworkInfo, len(cp.status.visibleNetworks))
	for i, net := range cp.status.visibleNetworks {
		//nolint:gosec
		networks[i] = provisioning.NetworkInfoToProto(&net)
	}

	return &pb.GetNetworkListResponse{Networks: networks}, nil
}

func (cp *CaptivePortal) errListAsStrings() []string {
	errList := make([]string, len(cp.status.errors))
	for i, err := range cp.status.errors {
		errList[i] = err.Error()
	}
	return errList
}
