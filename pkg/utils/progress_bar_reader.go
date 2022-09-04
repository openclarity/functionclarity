package utils

import (
	"github.com/vbauerster/mpb/v5"
	"os"
	"sync"
)

type ProgressBarReader struct {
	Fp      *os.File
	Size    int64
	read    int64
	Bar     *mpb.Bar
	SignMap map[int64]struct{}
	mux     sync.Mutex
}

func (r *ProgressBarReader) Read(p []byte) (int, error) {
	return r.Fp.Read(p)
}

func (r *ProgressBarReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.Fp.ReadAt(p, off)
	if err != nil {
		return n, err
	}

	r.Bar.SetTotal(r.Size, false)

	r.mux.Lock()
	// Ignore the first signature call
	if _, ok := r.SignMap[off]; ok {
		r.read += int64(n)
		r.Bar.SetCurrent(r.read)
	} else {
		r.SignMap[off] = struct{}{}
	}
	r.mux.Unlock()

	return n, err
}

func (r *ProgressBarReader) Seek(offset int64, whence int) (int64, error) {
	return r.Fp.Seek(offset, whence)
}
