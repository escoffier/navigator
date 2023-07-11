package all

import (
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/containerd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/docker"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/assets"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/avira"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/cache"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/stream"
	_ "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/tasks"
)
