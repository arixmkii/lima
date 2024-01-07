package osutil

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
)

func callcmd(args []string, env []string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	if (env != nil) {
		cmd.Env = append(cmd.Env, env...)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	logrus.Debugf("Executing command: %v", cmd.Args)
	out, err := cmd.Output()
	logrus.Debugf("%q (%v) exited: stdout=%q, stderr=%q, err=%v", args[0], cmd.Args, string(out), stderr.String(), err)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func ToCygpath(p string) string {
	cp, _ := callcmd([]string{"cygpath", "-u", p}, nil)
	cd := path.Dir(cp)
	cf := path.Base(cp)
	h := sha256.New()
	h.Write([]byte(cd))
	sha256_hash := hex.EncodeToString(h.Sum(nil))
	td := path.Join("/tmp", sha256_hash)
	_, err := callcmd([]string{"test", "-d", td}, nil)
	if err == nil {
		return path.Join(td, cf)
	}
	_, err = callcmd([]string{"ln", "-s", cd, td}, []string{"MSYS=winsymlinks:nativestrict"})
	if err == nil {
		return path.Join(td, cf)
	}
	return cp
}
