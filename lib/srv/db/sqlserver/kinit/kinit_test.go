// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
var cacheData []byte
var badCacheData = []byte("bad cache data to write to file")

type staticCache struct {
	t    *testing.T
	pass bool
}

type badCache struct {
	t *testing.T
}

func (b *badCache) CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cachePath := args[len(args)-1]
	require.NotEmpty(b.t, cachePath)
	err := os.WriteFile(cachePath, badCacheData, 0664)
	require.NoError(b.t, err)

	return exec.Command("echo")
}

func (s *staticCache) CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cachePath := args[len(args)-1]
	require.NotEmpty(s.t, cachePath)
	err := os.WriteFile(cachePath, cacheData, 0664)
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

func step(t *testing.T, name string, cg CommandGenerator, c *testCertGetter, expectErr func(t require.TestingT, err error, msgAndArgs ...interface{}), expectNil func(t require.TestingT, object interface{}, msgAndArgs ...interface{})) *testCase {
	dir := t.TempDir()
	var err error
	dir, err = os.MkdirTemp(dir, "krb5_cache")
	require.NoError(t, err)

	return &testCase{
		name: name,
		initializer: New(NewCommandLineInitializerWithCommand(nil,
			"alice",
			"example.com",
			"host.example.com",
			"host.example.com",
			dir, nil, cg, c)),
		expectErr:      expectErr,
		expectCacheNil: expectNil,
	}
}

func TestNewWithCommandLineProvider(t *testing.T) {

	cases := []*testCase{
		step(t, "TestCommandSuccessCase", &staticCache{t: t, pass: true}, &testCertGetter{pass: true}, require.NoError, require.NotNil),
		step(t, "TestCertificateFailureCase", &staticCache{t: t, pass: true}, &testCertGetter{pass: false}, require.Error, require.Nil),
		step(t, "TestCommandFailureCase", &staticCache{t: t, pass: false}, &testCertGetter{pass: true}, require.Error, require.Nil),
		// Final case returns an error along with a non nil credentials cache that essentially has all zeroed fields;
		// &credentials.CCache{Version:0x0, Header:credentials.header{length:0x0, fields:[]credentials.headerField(nil)}, DefaultPrincipal:credentials.principal{Realm:"", PrincipalName:types.PrincipalName{NameType:0, NameString:[]string(nil)}}, Credentials:[]*credentials.Credential(nil), Path:""}
		step(t, "TestBadCacheData", &badCache{t: t}, &testCertGetter{pass: true}, require.Error, require.NotNil),
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cc, err := c.initializer.UseOrCreateCredentialsCache(context.Background())
			c.expectErr(t, err)
			c.expectCacheNil(t, cc)
		})
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

	tmp := t.TempDir()

	f := filepath.Join(tmp, "krb.conf")
	err := cli.WriteKRB5Config(f)
	require.NoError(t, err)

	data, err := os.ReadFile(f)
	require.NoError(t, err)

	require.Equal(t, expectedConfString, string(data))
}
