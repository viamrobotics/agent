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
)

type CreatorFunc func(ctx context.Context, logger *zap.SugaredLogger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error)

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
