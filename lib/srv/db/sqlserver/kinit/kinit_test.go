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

//go:embed testdata/kinit.cache
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

func (t *testCertGetter) GetCertificateBytes(context.Context) (*WindowsCAAndKeyPair, error) {
	if t.pass {
		return &WindowsCAAndKeyPair{}, nil
	}
	return nil, errors.New("could not get cert bytes")

}

type testCase struct {
	name           string
	initializer    *PKInit
	expectErr      func(t require.TestingT, err error, msgAndArgs ...interface{})
	expectCacheNil func(t require.TestingT, object interface{}, msgAndArgs ...interface{})
}

func step(t *testing.T, name string, s *staticCache, c *testCertGetter, expectErr func(t require.TestingT, err error, msgAndArgs ...interface{}), expectNil func(t require.TestingT, object interface{}, msgAndArgs ...interface{})) *testCase {
	dir := t.TempDir()
	var err error
	dir, err = os.MkdirTemp(dir, "krb5_cache")
	require.NoError(s.t, err)

	return &testCase{
		name: name,
		initializer: New(NewCommandLineInitializerWithCommand(nil,
			"alice",
			"example.com",
			"host.example.com",
			"host.example.com",
			dir, nil, s, c)),
		expectErr:      expectErr,
		expectCacheNil: expectNil,
	}
}

func TestNewWithCommandLineProvider(t *testing.T) {

	cases := []*testCase{
		step(t, "TestKInitCommandSuccessCase", &staticCache{t: t, pass: true}, &testCertGetter{pass: true}, require.NoError, require.NotNil),
		step(t, "TestKInitCertificateFailureCase", &staticCache{t: t, pass: true}, &testCertGetter{pass: false}, require.Error, require.Nil),
		step(t, "TestKInitCommandFailureCase", &staticCache{t: t, pass: false}, &testCertGetter{pass: true}, require.Error, require.Nil),
	}

	for _, c := range cases {
		require.True(t, t.Run(c.name, func(t *testing.T) {
			cc, err := c.initializer.UseOrCreateCredentialsCache(context.Background())
			c.expectErr(t, err)
			c.expectCacheNil(t, cc)
		}))
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
