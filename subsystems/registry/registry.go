// Package registry is used to register subsystems from other packages.
package registry

import (
	"context"
	"sync"

	"github.com/viamrobotics/agent/subsystems"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
)

var (
	mu       sync.Mutex
	creators = map[string]CreatorFunc{}
)

type CreatorFunc func(ctx context.Context, logger logging.Logger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error)

func Register(name string, creator CreatorFunc) {
	mu.Lock()
	defer mu.Unlock()
	creators[name] = creator
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
