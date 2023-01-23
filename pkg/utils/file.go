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
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func DownloadFile(fileName string, url *string) error {

	// Get the data
	resp, err := http.Get(*url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(FunctionClarityHomeDir + fileName)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func ExtractZip(zipPath string, dstToExtract string) error {

	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open archive file : %s. %v", zipPath, err)
	}
	defer archive.Close()

	for _, f := range archive.File {
		filePath := filepath.Join(dstToExtract, f.Name)

		if !strings.HasPrefix(filePath, filepath.Clean(dstToExtract)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path")
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create directory for path: %s. %v", filePath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directories for path: %s. %v", filePath, err)
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("failed to open destination file for writing: %s. %v", filePath, err)
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in archive : %s. %v", f.Name, err)
		}

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			return fmt.Errorf("failed to copy file: %s from archive to local path: %s. %v", f.Name, dstFile.Name(), err)
		}

		dstFile.Close()
		fileInArchive.Close()
	}
	return nil
}

func CleanDirectory(directory string) {
	if err := os.RemoveAll(directory); err != nil {
		fmt.Printf("failed to delete directory %v: %v", directory, err)
	}
}
