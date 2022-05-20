package util

import (
	"net"
)

func GetMacAddrs() (macAddrs []string, err error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return macAddrs, err
	}

	for _, netInterface := range netInterfaces {
		macAddr := netInterface.HardwareAddr.String()
		if len(macAddr) == 0 {
			continue
		}

		macAddrs = append(macAddrs, macAddr)
	}
	return macAddrs, nil
}

func GetIPs() (ips []string, err error) {
	interfaceAddr, err := net.InterfaceAddrs()
	if err != nil {
		return ips, err
	}

	for _, address := range interfaceAddr {
		ipNet, isValidIpNet := address.(*net.IPNet)
		if isValidIpNet && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	return ips, nil
}
