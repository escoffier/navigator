package all

import (
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer/devicemapper"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer/imagetar"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer/overlay-crio"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer/overlay2"
)
