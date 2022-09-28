// Copyright © 2022 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
