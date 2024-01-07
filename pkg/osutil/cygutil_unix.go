//go:build !windows

package osutil

func ToCygpath(p string) string {
	return p
}
