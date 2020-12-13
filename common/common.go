package common

import (
	"errors"
	"net"
)

var (
	ErrNoInterfaceFound = errors.New("could not find interface with that name")
)

func GetMacAddr(name string) (string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifa := range ifas {
		if ifa.Name == name {
			return ifa.HardwareAddr.String(), nil
		}

	}
	return "", ErrNoInterfaceFound
}
