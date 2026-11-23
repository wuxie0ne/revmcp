package fsread

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/revmcp/revmcp/proto"
)

// Download applies the same path rules as Read, with a binary-safe size limit.
func (r *Reader) Download(ctx context.Context, path string) (*proto.FileDownload, error) {
	path, err := transferPath(path)
	if err != nil {
		return nil, err
	}
	if err := r.checkPathPolicy(path); err != nil {
		return nil, err
	}
	parent, err := openTransferParent(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()
	// O_PATH pins the inode for inspection without opening a device or FIFO for I/O.
	const oPath = 0x200000
	fd, err := syscall.Openat(int(parent.Fd()), filepath.Base(path), oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	handle := os.NewFile(uintptr(fd), path)
	defer func() { _ = handle.Close() }()
	stat, err := handle.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > proto.MaxFileTransferBytes {
		return nil, fmt.Errorf("%w: expected a regular file of at most %d bytes", ErrInvalidPath, proto.MaxFileTransferBytes)
	}
	file, err := os.Open(descriptorPath(handle))
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, proto.MaxFileTransferBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > proto.MaxFileTransferBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", ErrInvalidPath, proto.MaxFileTransferBytes)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	meta, payload, err := proto.EncodeFilePayload(data)
	if err != nil {
		return nil, err
	}
	return &proto.FileDownload{FileTransferResult: meta, Data: payload}, nil
}

// Upload writes a verified file into the destination without following symlinks.
func (r *Reader) Upload(ctx context.Context, req proto.FSUploadRequest, payload []byte) (*proto.FileTransferResult, error) {
	path, err := transferPath(req.Path)
	if err != nil {
		return nil, err
	}
	if err := r.checkDeniedPaths(path, path); err != nil {
		return nil, err
	}
	data, err := proto.DecodeFilePayload(req.FileTransferResult, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPath, err)
	}
	parent, err := openTransferParent(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()

	// The pinned descriptor keeps publication in the same directory if it is moved.
	dir := descriptorPath(parent)
	dst := filepath.Join(dir, filepath.Base(path))
	if err := checkUploadDestination(dst, req.Overwrite); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".revmcp-upload-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, writeErr := tmp.Write(data)
	if writeErr == nil {
		writeErr = tmp.Sync()
	}
	if err := errors.Join(writeErr, tmp.Close()); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Overwrite {
		err = os.Rename(tmp.Name(), dst)
	} else {
		// Linking the staged file atomically refuses an existing destination.
		err = os.Link(tmp.Name(), dst)
	}
	if err != nil {
		return nil, err
	}
	return &req.FileTransferResult, nil
}

func transferPath(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) || len(path) > 4096 {
		return "", fmt.Errorf("%w: expected an absolute file path of at most 4096 bytes", ErrInvalidPath)
	}
	cleaned := filepath.Clean(path)
	if cleaned != path || cleaned == "/" {
		return "", fmt.Errorf("%w: expected a clean path to a file", ErrInvalidPath)
	}
	return cleaned, nil
}

func openTransferParent(path string) (*os.File, error) {
	const flags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open("/", flags, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := syscall.Openat(fd, part, flags, 0)
		_ = syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), filepath.Dir(path)), nil
}

func descriptorPath(file *os.File) string {
	return fmt.Sprintf("/proc/self/fd/%d", file.Fd())
}

func checkUploadDestination(path string, overwrite bool) error {
	stat, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() {
		return fmt.Errorf("%w: destination is not a regular file", ErrInvalidPath)
	}
	if !overwrite {
		return os.ErrExist
	}
	return nil
}
