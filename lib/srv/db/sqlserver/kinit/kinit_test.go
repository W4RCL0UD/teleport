package kinit

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:embed kinit.cache
var cache []byte

type staticCache struct {
	t    *testing.T
	pass bool
}

func (s *staticCache) CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cachePath := args[len(args)-1]
	require.NotEmpty(s.t, cachePath)
	err := os.WriteFile(cachePath, cache, 0664)
	require.NoError(s.t, err)

	if s.pass {
		return exec.Command("echo")
	}
	cmd := exec.Command("")
	cmd.Err = errors.New("bad command")
	return cmd

}

type testCertGetter struct {
	pass bool
}

func (t *testCertGetter) GetCertificateBytes(context.Context) ([]byte, []byte, []byte, error) {
	if t.pass {
		return nil, nil, nil, nil
	}
	return nil, nil, nil, errors.New("could not get cert bytes")

}

type testStep struct {
	initializer *PKInit
	expectErr   func(t require.TestingT, err error, msgAndArgs ...interface{})
	expectNil   func(t require.TestingT, object interface{}, msgAndArgs ...interface{})
	post        func() error
}

func step(s *staticCache, c *testCertGetter, expectErr func(t require.TestingT, err error, msgAndArgs ...interface{}), expectNil func(t require.TestingT, object interface{}, msgAndArgs ...interface{})) *testStep {
	dir, err := os.MkdirTemp("", "krb5_cache")
	require.NoError(s.t, err)

	return &testStep{
		initializer: New(NewCommandLineInitializerWithCommand(nil,
			"alice",
			"example.com",
			"host.example.com",
			"host.example.com",
			dir, nil, s, c)),
		expectErr: expectErr,
		expectNil: expectNil,
		post: func() error {
			return os.RemoveAll(dir)
		},
	}
}

func TestNewWithCommandLineProvider(t *testing.T) {

	steps := []*testStep{
		step(&staticCache{t: t, pass: true}, &testCertGetter{pass: true}, require.NoError, require.NotNil),
		step(&staticCache{t: t, pass: true}, &testCertGetter{pass: false}, require.Error, require.Nil),
		step(&staticCache{t: t, pass: false}, &testCertGetter{pass: true}, require.Error, require.Nil),
		step(&staticCache{t: t, pass: false}, &testCertGetter{pass: false}, require.Error, require.Nil),
	}

	for _, s := range steps {
		cc, err := s.initializer.UseOrCreateCredentialsCache(context.Background())
		s.expectErr(t, err)
		s.expectNil(t, cc)
		require.NoError(t, s.post())
	}

}

const (
	expectedConfString = `[libdefaults]
 default_realm = example.com
 rdns = false


[realms]
 example.com = {
  kdc = host.example.com
  admin_server = host.example.com
  pkinit_eku_checking = kpServerAuth
  pkinit_kdc_hostname = host.example.com
 }`
)

func TestKRBConfString(t *testing.T) {
	cli := NewCommandLineInitializerWithCommand(nil,
		"alice",
		"example.com",
		"host.example.com",
		"host.example.com",
		"",
		nil, &staticCache{t: t, pass: true}, &testCertGetter{pass: true})

	tmp, err := os.MkdirTemp("", "kinit")
	require.NoError(t, err)

	defer func() {
		err = os.RemoveAll(tmp)
		require.NoError(t, err)
	}()
	f := filepath.Join(tmp, "krb.conf")
	err = cli.WriteKRB5Config(f)
	require.NoError(t, err)

	data, err := os.ReadFile(f)
	require.NoError(t, err)

	require.Equal(t, expectedConfString, string(data))
}
