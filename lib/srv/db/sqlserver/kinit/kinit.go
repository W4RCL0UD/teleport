// Copyright 2022 Gravitational, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package kinit provides utilities for interacting with a KDC (Key Distribution Center) for Kerberos5
package kinit

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"

	"github.com/gravitational/trace"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/windows"
)

const (
	// krb5ConfigEnv sets the location from which kinit will attempt to read a configuration value
	krb5ConfigEnv = "KRB5_CONFIG"
	// kinitBinary is the binary name for the kinit executable
	kinitBinary = "kinit"
	// krb5ConfigTemplate is a configuration template suitable for x509 configuration; it is read by the kinit binary
	krb5ConfigTemplate = `[libdefaults]
 default_realm = {{ .RealmName }}
 rdns = false


[realms]
 {{ .RealmName }} = {
  kdc = {{ .KDCHostName }}
  admin_server = {{ .AdminServerName }}
  pkinit_eku_checking = kpServerAuth
  pkinit_kdc_hostname = {{ .KDCHostName }}
 }`
)

// Provider is a kinit provider capable of producing a credentials cache for kerberos
type Provider interface {
	// UseOrCreateCredentials uses or updates an existing cache or creates a new one
	UseOrCreateCredentials(ctx context.Context) (cache *credentials.CCache, err error)
}

// PKInit is a structure used for initializing a kerberos context
type PKInit struct {
	provider Provider
}

// UseOrCreateCredentialsCache uses or creates a credentials cache.
func (k *PKInit) UseOrCreateCredentialsCache(ctx context.Context) (*credentials.CCache, error) {
	return k.provider.UseOrCreateCredentials(ctx)
}

// New returns a new PKInit initializer
func New(provider Provider) *PKInit {
	return &PKInit{provider: provider}
}

// NewWithCommandLineProvider returns a new PKInit instance using a command line `kinit` binary
func NewWithCommandLineProvider(authClient auth.ClientI, user, realm, kdcHost, adminServer, dataDir string, ldapCA *x509.Certificate, certGetter CertGetter) *PKInit {
	return &PKInit{provider: NewCommandLineInitializer(authClient, user, realm, kdcHost, adminServer, dataDir, ldapCA, certGetter)}
}

// NewCommandLineInitializer returns a new command line initializer using a preinstalled `kinit` binary
func NewCommandLineInitializer(authClient auth.ClientI, user, realm, kdcHost, adminServer, dataDir string, ldapCA *x509.Certificate, certGetter CertGetter) *CommandLineInitializer {
	return NewCommandLineInitializerWithCommand(authClient, user, realm, kdcHost, adminServer, dataDir, ldapCA, &execCmd{}, certGetter)
}

// NewCommandLineInitializerWithCommand returns a new command line initializer using a preinstalled `kinit` binary
func NewCommandLineInitializerWithCommand(authClient auth.ClientI, user, realm, kdcHost, adminServer, dataDir string, ldapCA *x509.Certificate, command commandGenerator, certGetter CertGetter) *CommandLineInitializer {
	return &CommandLineInitializer{
		auth:            authClient,
		userName:        user,
		cacheName:       fmt.Sprintf("%s@%s", user, realm),
		RealmName:       realm,
		KDCHostName:     kdcHost,
		AdminServerName: adminServer,
		dataDir:         dataDir,
		certPath:        fmt.Sprintf("%s.pem", user),
		keyPath:         fmt.Sprintf("%s-key.pem", user),
		binary:          kinitBinary,
		command:         command,
		certGetter:      certGetter,
		ldapCertificate: ldapCA,
		log:             logrus.StandardLogger(),
	}
}

// commandGenerator is a small interface for wrapping *exec.Cmd
type commandGenerator interface {
	// CommandContext is a wrapper for creating a command
	CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd
}

// execCmd is a small wrapper around exec.Cmd
type execCmd struct {
}

// CommandContext returns exec.CommandContext
func (*execCmd) CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

// CommandLineInitializer uses a command line `kinit` binary to provide a kerberos CCache
type CommandLineInitializer struct {
	auth auth.ClientI

	// RealmName is the kerberos realm name (domain name, like `example.com`
	RealmName string
	// KDCHostName is the key distribution center host name (usually AD host, like ad.example.com)
	KDCHostName string
	// AdminServerName is the admin server name (usually AD host)
	AdminServerName string

	dataDir   string
	userName  string
	cacheName string

	certPath string
	keyPath  string
	binary   string

	command    commandGenerator
	certGetter CertGetter

	ldapCertificate *x509.Certificate
	log             logrus.FieldLogger
}

// CertGetter is an interface for getting a new cert/key pair along with a CA cert
type CertGetter interface {
	// GetCertificateBytes returns a new cert/key pair along with a CA for use with x509 Auth
	GetCertificateBytes(ctx context.Context) (certPEM, keyPEM, caCert []byte, err error)
}

// DBCertGetter obtains a new cert/key pair along with the Teleport database CA
type DBCertGetter struct {
	// Auth is the auth client
	Auth auth.ClientI
	// KDCHostName is the name of the key distribution center host
	KDCHostName string
	// RealmName is the kerberos realm name (domain name)
	RealmName string
	// AdminServerName is the name of the admin server. Usually same as the KDC
	AdminServerName string
	// UserName is the database username
	UserName string
	// LDAPCA is the windows ldap certificate
	LDAPCA *x509.Certificate
}

// GetCertificateBytes returns a new cert/key pem and the DB CA bytes
func (d *DBCertGetter) GetCertificateBytes(ctx context.Context) (certPEM, keyPEM, caCert []byte, err error) {
	clusterName, err := d.Auth.GetClusterName()
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	certPEM, keyPEM, err = windows.CertKeyPEM(ctx, d.UserName, d.RealmName, time.Second*60*60, clusterName.GetClusterName(), windows.LDAPConfig{
		Addr:               d.KDCHostName,
		Domain:             d.RealmName,
		Username:           d.UserName,
		InsecureSkipVerify: false,
		ServerName:         d.AdminServerName,
		CA:                 d.LDAPCA,
	}, d.Auth)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	dbCA, err := d.Auth.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.DatabaseCA,
		DomainName: clusterName.GetClusterName(),
	}, true)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	keyPairs := dbCA.GetActiveKeys().TLS
	for _, keyPair := range keyPairs {
		if keyPair.KeyType == types.PrivateKeyType_RAW {
			caCert = keyPair.Cert
		}
	}

	if caCert == nil {
		return nil, nil, nil, trace.Wrap(errors.New("no certificate authority was found in userCA active keys"))
	}

	return
}

// UseOrCreateCredentials uses an existing cache or creates a new one
func (k *CommandLineInitializer) UseOrCreateCredentials(ctx context.Context) (*credentials.CCache, error) {
	tmp, err := os.MkdirTemp("", "kinit")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	defer func() {
		err = os.RemoveAll(tmp)
		if err != nil {
			k.log.WithError(err).Error("Failed to clear up kinit temporary directory)
		}
	}()

	certPath := filepath.Join(tmp, fmt.Sprintf("%s.pem", k.userName))
	keyPath := filepath.Join(tmp, fmt.Sprintf("%s-key.pem", k.userName))
	userCAPath := filepath.Join(tmp, "userca.pem")

	cacheDir := filepath.Join(k.dataDir, "krb5_cache")

	err = os.MkdirAll(cacheDir, os.ModePerm)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cachePath := filepath.Join(cacheDir, k.cacheName)

	var certPEM, keyPEM, caCert []byte

	certPEM, keyPEM, caCert, err = k.certGetter.GetCertificateBytes(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// store files in temp dir
	err = os.WriteFile(certPath, certPEM, 0644)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = os.WriteFile(keyPath, keyPEM, 0644)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = os.WriteFile(userCAPath, caCert, 0644)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	krbConfPath := filepath.Join(tmp, fmt.Sprintf("krb_%s", k.userName))
	err = k.WriteKRB5Config(krbConfPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cmd := k.command.CommandContext(ctx,
		k.binary,
		"-X", fmt.Sprintf("X509_anchors=FILE:%s", certPath),
		"-X", fmt.Sprintf("X509_user_identity=FILE:%s,%s", certPath, keyPath), k.userName,
		"-c", cachePath)

	if cmd.Err != nil {
		return nil, trace.Wrap(cmd.Err)
	}

	cmd.Env = append(cmd.Env, []string{fmt.Sprintf("%s=%s", krb5ConfigEnv, krbConfPath)}...)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return credentials.LoadCCache(cachePath)
}

// krb5ConfigString returns a config suitable for a kdc
func (k *CommandLineInitializer) krb5ConfigString() (string, error) {
	t, err := template.New("krb_conf").Parse(krb5ConfigTemplate)

	if err != nil {
		return "", trace.Wrap(err)
	}
	b := bytes.NewBuffer([]byte{})
	err = t.Execute(b, k)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return b.String(), nil
}

// WriteKRB5Config writes a krb configuration to path
func (k *CommandLineInitializer) WriteKRB5Config(path string) error {
	s, err := k.krb5ConfigString()
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.ConvertSystemError(os.WriteFile(path, []byte(s), 0644))
}
