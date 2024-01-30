// Package registry is used to register subsystems from other packages.
package registry

import (
	"context"
	"sync"

	"github.com/viamrobotics/agent/subsystems"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
)

var (
	mu       sync.Mutex
	creators = map[string]CreatorFunc{}
	configs  = map[string]*pb.DeviceSubsystemConfig{}
)

type CreatorFunc func(ctx context.Context, logger *zap.SugaredLogger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error)

func Register(name string, creator CreatorFunc, cfg *pb.DeviceSubsystemConfig) {
	mu.Lock()
	defer mu.Unlock()
	creators[name] = creator
	configs[name] = cfg
}

func Deregister(name string) {
	mu.Lock()
	defer mu.Unlock()
	delete(creators, name)
}

func GetCreator(name string) CreatorFunc {
	mu.Lock()
	defer mu.Unlock()
	creator, ok := creators[name]
	if ok {
		return creator
	}
	return nil
}

func GetDefaultConfig(name string) *pb.DeviceSubsystemConfig {
	mu.Lock()
	defer mu.Unlock()
	cfg, ok := configs[name]
	if ok {
		return cfg
	}
	return nil
}

func List() []string {
	mu.Lock()
	defer mu.Unlock()
	//nolint:prealloc
	var names []string
	for k := range creators {
		names = append(names, k)
	}
	return names
}
