package networkmanager

import (
	"encoding/binary"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	"go.uber.org/zap"
	pb "go.viam.com/api/provisioning/v1"
	"google.golang.org/grpc"

	provisioning "github.com/viamrobotics/agent-provisioning"
)

// This file contains type, const, and var definitions.

const (
	DNSMasqFilepath          = "/etc/NetworkManager/dnsmasq-shared.d/80-viam.conf"
	DNSMasqContentsRedirect  = "address=/#/10.42.0.1\n"
	DNSMasqContentsSetupOnly = "address=/.setup/10.42.0.1\n"

	ConnCheckFilepath = "/etc/NetworkManager/conf.d/80-viam.conf"
	ConnCheckContents = "[connectivity]\nuri=http://packages.viam.com/check_network_status.txt\ninterval=300\n"

	NetworkTypeWifi    = "wifi"
	NetworkTypeHotspot = "hotspot"
	NetworkTypeWired   = "wired"
)

var (
	BindAddr = "10.42.0.1"
	// older networkmanager requires unit32 arrays for IP addresses.
	IPAsUint32                 = binary.LittleEndian.Uint32([]byte{10, 42, 0, 1})
	ErrBadPassword             = errors.New("bad or missing password")
	ErrConnCheckDisabled       = errors.New("NetworkManager connectivity checking disabled by user, network management will be unavailable")
	ErrNoActiveConnectionFound = errors.New("no active connection found")
	mainLoopDelay              = time.Second * 1
	scanLoopDelay              = time.Second * 15
	connectTimeout             = time.Second * 50 // longer than the 45 second timeout in NetworkManager
)

type NMWrapper struct {
	monitorWorkers      sync.WaitGroup
	provisioningWorkers sync.WaitGroup

	// blocks start/stop/etc operations
	// holders of this lock must use HealthySleep to respond to HealthChecks from the parent agent during long operations
	opMu sync.Mutex

	// only set during NewNMWrapper, no lock
	nm          gnm.NetworkManager
	dev         gnm.DeviceWireless
	settings    gnm.Settings
	hostname    string
	logger      *zap.SugaredLogger
	cfg         provisioning.Config
	viamCfgPath string

	// internal locking
	state *connectionState

	// locking for data updates
	dataMu      sync.Mutex

	// key is interface@ssid for wifi, ex: wlan0@TestNetwork
	// interface may be "any" for no interface set, ex: any@TestNetwork
	// wired networks are just interface, ex: eth0
	networks    map[string]*network

	// the wifi device used by provisioning and actively managed for connectivity
	hotspotInterface string
	hotspotSSID string
	lastSSID    string

	// key is interface name, ex: wlan0
	primarySSID map[string]string
	activeSSID  map[string]string

	errors      []error

	// portal
	webServer  *http.Server
	grpcServer *grpc.Server

	input         *provisioning.UserInput
	inputReceived atomic.Bool
	banner        string
	pb.UnimplementedProvisioningServiceServer
}

type network struct {
	netType   string
	ssid      string
	security  string
	signal    uint8
	priority  int32
	isHotspot bool

	firstSeen time.Time
	lastSeen  time.Time

	lastTried     time.Time
	connected     bool
	lastConnected time.Time
	lastError     error
	interfaceName string

	conn       gnm.Connection
	activeConn gnm.ActiveConnection
}

func (n *network) getInfo() provisioning.NetworkInfo {
	var errStr string
	if n.lastError != nil {
		errStr = n.lastError.Error()
	}

	return provisioning.NetworkInfo{
		Type:      n.netType,
		SSID:      n.ssid,
		Security:  n.security,
		Signal:    int32(n.signal),
		Connected: n.connected,
		LastError: errStr,
	}
}
