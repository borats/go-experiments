// +build linux darwin openbsd
// +build amd64

package main

import (
	"syscall"
)

var (
	unit           float64
	unitStr        string
	totalSizeBytes float64
	statfs         syscall.Statfs_t
)

const (
	TByte = 1024.0 * 1024.0 * 1024 * 1024
	GByte = TByte / 1024.0
	MByte = GByte / 1024.0
	KByte = MByte / 1024.0
)

type diskSize struct {
	total     float64
	available float64
	statfs    syscall.Statfs_t
}

func diskCalc() (*diskSize, error) {
	if err := syscall.Statfs(*path, &statfs); err != nil {
		return nil, err
	}
	totalSizeBytes = float64(statfs.Blocks) * float64(statfs.Bsize)
	if totalSizeBytes >= KByte && totalSizeBytes <= MByte {
		unit = KByte
		unitStr = "KB"
	} else if totalSizeBytes >= MByte && totalSizeBytes <= GByte {
		unit = MByte
		unitStr = "MB"
	} else if totalSizeBytes >= GByte && totalSizeBytes <= TByte {
		unit = GByte
		unitStr = "GB"
	} else if totalSizeBytes >= TByte {
		unit = TByte
		unitStr = "TB"
	}
	return &diskSize{
		total:     totalSizeBytes / unit,
		available: (float64(statfs.Bavail) * float64(statfs.Bsize)) / unit,
		statfs:    statfs,
	}, nil
}
