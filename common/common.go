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

func GetMacMTU(name string) (int, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return -1, err
	}
	for _, ifa := range ifas {
		if ifa.Name == name {
			return ifa.MTU, nil
		}

	}
	return -1, ErrNoInterfaceFound
}
