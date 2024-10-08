// Copyright 2024 go-dataspace
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fsprovider implements a simple RUN-DSP server using files in a directory structure
// as dataset entries.
// TODO: Describe how path is ascertained from Aiuth
// IMPORTANT: This provider is not meant for production use, it is just to demonstrate how to
// implement a RUN-DSP provider, IDs also don't persist through restarts.
package fsprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/go-dataspace/reference-provider/internal/authprocessor"
	providerv1alpha1 "github.com/go-dataspace/run-dsrpc/gen/go/dsp/v1alpha1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	providerName        = "reference-provider"
	providerDescription = "Reference filesystem provider for RUN-DSP."
)

// fileInfo is a small struct to keep file info together.
type fileInfo struct {
	ID       uuid.UUID
	FullPath string
	DirEntry fs.DirEntry
}

// Server implements both the ProviderService, and the publish http handler.
type Server struct {
	providerv1alpha1.UnimplementedProviderServiceServer

	dir         fs.FS
	filesByID   map[uuid.UUID]*fileInfo
	registry    *publishRegistry
	publishRoot *url.URL
}

// New creates a new provider service. dir is the root of the files, pubishRoot is the URL the
// mux is mounted under.
func New(ctx context.Context, dir string, publishRoot *url.URL) (*Server, error) {
	rootFS := os.DirFS(dir)
	fbid := make(map[uuid.UUID]*fileInfo)
	err := fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		id := uuid.New()
		fbid[id] = &fileInfo{
			ID:       id,
			FullPath: path,
			DirEntry: d,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Server{
		dir:         rootFS,
		filesByID:   fbid,
		registry:    newPublishRegistry(),
		publishRoot: publishRoot,
	}, nil
}

// Ping sends back some basic info.
func (s *Server) Ping(ctx context.Context, req *providerv1alpha1.PingRequest) (*providerv1alpha1.PingResponse, error) {
	prefix := authprocessor.ExtractPrefix(ctx)
	return &providerv1alpha1.PingResponse{
		ProviderName:        providerName,
		ProviderDescription: providerDescription,
		Authenticated:       prefix != "",
		DataserviceUrl:      s.publishRoot.String(),
		DataserviceId:       s.generateConsistentID(),
	}, nil
}

// generateConsistentID generates a UUID URN based on the publishroot port and hostname.
// We put the port first as only the first 16 bytes matter and if we're running on the same host
// as other providers, the port will be the only change.
func (s *Server) generateConsistentID() string {
	// uuid generation needs 16 bytes
	randBuf := make([]byte, 16)
	initSeed := []byte(fmt.Sprintf("%s%s", s.publishRoot.Port(), s.publishRoot.Hostname()))

	// Copy the initial seed into the buffer
	copy(randBuf, initSeed)

	// If the initial seed wasn't 16 bytes, fill it up with X's
	if len(initSeed) < 16 {
		copy(randBuf[len(initSeed):], "XXXXXXXXXXXXXXXXXXX")
	}

	u, err := uuid.NewRandomFromReader(bytes.NewReader(randBuf))
	if err != nil {
		// If this fails, return a random URN.
		return uuid.New().URN()
	}

	return u.URN()
}

// GetCatalogue finds all the files that match the current authentication information, and
// converts them into a list of datasets.
func (s *Server) GetCatalogue(
	ctx context.Context, req *providerv1alpha1.GetCatalogueRequest,
) (*providerv1alpha1.GetCatalogueResponse, error) {
	prefix := authprocessor.ExtractPrefix(ctx)
	matchingFiles := make([]*fileInfo, 0)
	for _, v := range s.filesByID {
		if strings.HasPrefix(v.FullPath, prefix) {
			matchingFiles = append(matchingFiles, v)
		}
	}

	catalogue, err := makeCatalogue(s.dir, matchingFiles)
	if err != nil {
		return nil, fmt.Errorf("couldn't create catalogue: %w", err)
	}
	return &providerv1alpha1.GetCatalogueResponse{
		Datasets: catalogue,
	}, nil
}

// GetDataset looks up a file by the given ID and returns it as a dataset.
func (s *Server) GetDataset(
	ctx context.Context, req *providerv1alpha1.GetDatasetRequest,
) (*providerv1alpha1.GetDatasetResponse, error) {
	dsID, err := uuid.Parse(req.GetDatasetId())
	if err != nil {
		return nil, fmt.Errorf("invalid UUID: %w", err)
	}
	fi, ok := s.filesByID[dsID]
	if !ok {
		return nil, fmt.Errorf("dataset not found")
	}
	prefix := authprocessor.ExtractPrefix(ctx)
	if !strings.HasPrefix(fi.FullPath, prefix) {
		return nil, status.Errorf(codes.PermissionDenied, "not allowed to access dataset")
	}
	ds, err := fileInfoToDataset(s.dir, fi)
	if err != nil {
		return nil, err
	}
	return &providerv1alpha1.GetDatasetResponse{
		Dataset: ds,
	}, nil
}

// PublishDataset publishes a dataset, in our context that means a file.
func (s *Server) PublishDataset(
	ctx context.Context, req *providerv1alpha1.PublishDatasetRequest,
) (*providerv1alpha1.PublishDatasetResponse, error) {
	dsID, err := uuid.Parse(req.GetDatasetId())
	if err != nil {
		return nil, fmt.Errorf("invalid dataset UUID: %w", err)
	}
	pID, err := uuid.Parse(req.GetPublishId())
	if err != nil {
		return nil, fmt.Errorf("invalid publish UUID: %w", err)
	}
	fi, ok := s.filesByID[dsID]
	if !ok {
		return nil, fmt.Errorf("dataset not found")
	}
	prefix := authprocessor.ExtractPrefix(ctx)
	if !strings.HasPrefix(fi.FullPath, prefix) {
		return nil, status.Errorf(codes.PermissionDenied, "not allowed to access dataset")
	}
	token, err := generateRandomString(64)
	if err != nil {
		return nil, fmt.Errorf("could not generate random string")
	}
	identifier, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("could not generate random string")
	}
	pf := &publishedFile{
		ID:             pID,
		File:           fi,
		Token:          token,
		PathIdentifier: identifier,
	}
	s.registry.Put(pf)
	u, err := url.Parse(s.publishRoot.String())
	if err != nil {
		panic(fmt.Sprintf("invalid URL %s: %s", s.publishRoot.String(), err))
	}
	u.Path = path.Join(u.Path, pf.PathIdentifier, pf.File.DirEntry.Name())
	return &providerv1alpha1.PublishDatasetResponse{
		PublishInfo: &providerv1alpha1.PublishInfo{
			Url:                u.String(),
			AuthenticationType: providerv1alpha1.AuthenticationType_AUTHENTICATION_TYPE_BEARER,
			Username:           "",
			Password:           pf.Token,
		},
	}, nil
}

// UnpublishDataset unpublishes a dataset.
func (s *Server) UnpublishDataset(
	ctx context.Context, req *providerv1alpha1.UnpublishDatasetRequest,
) (*providerv1alpha1.UnpublishDatasetResponse, error) {
	pID, err := uuid.Parse(req.GetPublishId())
	if err != nil {
		return nil, fmt.Errorf("invalid publish UUID: %w", err)
	}
	pi := s.registry.GetByUUID(pID)
	if pi == nil {
		return &providerv1alpha1.UnpublishDatasetResponse{
			Success: true,
		}, nil
	}
	prefix := authprocessor.ExtractPrefix(ctx)
	if !strings.HasPrefix(pi.File.FullPath, prefix) {
		return nil, status.Errorf(codes.PermissionDenied, "not allowed to access dataset")
	}
	s.registry.Del(pID)
	return &providerv1alpha1.UnpublishDatasetResponse{
		Success: true,
	}, nil
}

func makeCatalogue(dir fs.FS, fi []*fileInfo) ([]*providerv1alpha1.Dataset, error) {
	datasets := make([]*providerv1alpha1.Dataset, len(fi))
	for i, f := range fi {
		ds, err := fileInfoToDataset(dir, f)
		if err != nil {
			return nil, err
		}
		datasets[i] = ds
	}
	return datasets, nil
}

func fileInfoToDataset(dir fs.FS, fi *fileInfo) (*providerv1alpha1.Dataset, error) {
	i, err := fi.DirEntry.Info()
	if err != nil {
		return nil, fmt.Errorf("couldn't get info for %s: %w", fi.DirEntry.Name(), err)
	}
	mimeType, err := detectMIMEType(dir, fi)
	if err != nil {
		return nil, fmt.Errorf("couldn't get mimetype for %s: %w", fi.DirEntry.Name(), err)
	}
	return &providerv1alpha1.Dataset{
		Id:            fi.ID.String(),
		Title:         fi.DirEntry.Name(),
		AccessMethods: "https",
		Modified:      timestamppb.New(i.ModTime()),
		MediaType:     mimeType.String(),
		ByteSize:      i.Size(),
	}, nil
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
