//go:build windows

/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slices"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/utils/keypaths"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client"
)

// the key should not include HKEY_CURRENT_USER
const puttyRegistryRootKey = `SOFTWARE\SimonTatham`
const puttyRegistryKey = puttyRegistryRootKey + `\PuTTY`
const puttyRegistrySessionsKey = puttyRegistryKey + `\Sessions`
const puttyRegistrySSHHostCAsKey = puttyRegistryKey + `\SshHostCAs`

// strings
const puttyProtocol = `ssh`
const puttyProxyTelnetCommand = `%tsh proxy ssh --cluster=%cluster --proxy=%proxyhost %user@%host:%port`

// ints
const puttyDefaultSSHPort = `3022`

// dwords
const puttyDwordPresent = `00000001`
const puttyDwordDontProxyDNS = `00000000`
const puttyDwordProxyDNS = `00000001`
const puttyDwordNoProxyMethod = `00000000`

const puttyDwordProxyMethod = `00000005` // run a local command
const puttyDwordProxyLogToTerm = `00000002`

// despite the strings in struct, these are stored in the registry as DWORDs
type puttyRegistrySessionDwords struct {
	Present        string // dword
	PortNumber     string // dword
	ProxyDNS       string // dword
	ProxyMethod    string // dword
	ProxyLogToTerm string // dword
}

type puttyRegistrySessionStrings struct {
	Hostname            string
	Protocol            string
	ProxyHost           string
	ProxyPort           string
	ProxyUsername       string
	ProxyPassword       string
	ProxyTelnetCommand  string
	PublicKeyFile       string
	DetachedCertificate string
	UserName            string
}

// addPuTTYSession adds a PuTTY session for the given host/port to the Windows registry
func addPuTTYSession(proxyHostname string, hostname string, login string, port string, ppkFilePath string, certificateFilePath string, commandToRun string) (bool, error) {
	registryKey := fmt.Sprintf(`%v\%v`, puttyRegistrySessionsKey, hostname)
	sessionDwords := puttyRegistrySessionDwords{}
	sessionStrings := puttyRegistrySessionStrings{}

	// if the proxy hostname is set to a dash, this is a non-proxied session (i.e. it's the
	// connection to the proxy itself) and we use the provided "hostname" value instead
	if proxyHostname == "-" {
		sessionDwords = puttyRegistrySessionDwords{
			Present:        puttyDwordPresent,
			PortNumber:     port,
			ProxyDNS:       puttyDwordDontProxyDNS,  // don't proxy DNS for root connection
			ProxyMethod:    puttyDwordNoProxyMethod, // no proxy method for root connections
			ProxyLogToTerm: puttyDwordProxyLogToTerm,
		}

		sessionStrings = puttyRegistrySessionStrings{
			Hostname:            hostname,
			Protocol:            puttyProtocol,
			ProxyHost:           "",
			ProxyPort:           "",
			ProxyUsername:       login,
			ProxyPassword:       "",
			ProxyTelnetCommand:  "",
			PublicKeyFile:       ppkFilePath,
			DetachedCertificate: certificateFilePath,
		}
	} else {
		sessionDwords = puttyRegistrySessionDwords{
			Present:        puttyDwordPresent,
			PortNumber:     puttyDefaultSSHPort, // default SSH port value goes here; this is a proxied connection and port is irrelevant
			ProxyDNS:       puttyDwordProxyDNS,
			ProxyMethod:    puttyDwordProxyMethod,
			ProxyLogToTerm: puttyDwordProxyLogToTerm,
		}

		sessionStrings = puttyRegistrySessionStrings{
			Hostname:            hostname,
			Protocol:            puttyProtocol,
			ProxyHost:           proxyHostname,
			ProxyPort:           port,
			ProxyUsername:       login,
			ProxyPassword:       "",
			ProxyTelnetCommand:  commandToRun,
			PublicKeyFile:       ppkFilePath,
			DetachedCertificate: certificateFilePath,
			UserName:            login,
		}
	}

	// now check for and create the individual session key
	pk, err := getRegistryKey(registryKey)
	if err != nil {
		return false, trace.Wrap(err)
	}
	defer pk.Close()

	// write dwords
	mustWriteDword(pk, "Present", sessionDwords.Present)
	mustWriteDword(pk, "PortNumber", sessionDwords.PortNumber)
	mustWriteDword(pk, "ProxyDNS", sessionDwords.ProxyDNS)
	mustWriteDword(pk, "ProxyMethod", sessionDwords.ProxyMethod)
	mustWriteDword(pk, "ProxyLogToTerm", sessionDwords.ProxyLogToTerm)

	// write strings
	mustWriteString(pk, "Hostname", sessionStrings.Hostname)
	mustWriteString(pk, "Protocol", sessionStrings.Protocol)
	mustWriteString(pk, "ProxyHost", sessionStrings.ProxyHost)
	mustWriteString(pk, "ProxyPort", sessionStrings.ProxyPort)
	mustWriteString(pk, "ProxyUsername", sessionStrings.ProxyUsername)
	mustWriteString(pk, "ProxyPassword", sessionStrings.ProxyPassword)
	mustWriteString(pk, "ProxyTelnetCommand", sessionStrings.ProxyTelnetCommand)
	mustWriteString(pk, "PublicKeyFile", sessionStrings.PublicKeyFile)
	mustWriteString(pk, "DetachedCertificate", sessionStrings.DetachedCertificate)
	mustWriteString(pk, "UserName", sessionStrings.UserName)

	return true, nil
}

// addHostCAPublicKey adds a host CA to the registry with a set of space-separated hostnames
func addHostCAPublicKey(keyName string, publicKey string, hostnames []string) (bool, error) {
	registryKeyName := fmt.Sprintf(`%v\%v`, puttyRegistrySSHHostCAsKey, keyName)

	// get the subkey with the host CA key name
	registryKey, err := getRegistryKey(registryKeyName)
	if err != nil {
		return false, trace.Wrap(err)
	}
	hostList, _, err := registryKey.GetStringsValue("MatchHosts")
	if err != nil {
		if len(hostList) == 0 {
			hostList = []string{}
		}
	} else {
		log.Debugf("Can't get registry key %v", registryKeyName)
		return false, trace.Wrap(err)
	}
	defer registryKey.Close()

	// add all wildcards to the host list first
	for _, host := range hostnames {
		if strings.HasPrefix(host, "*.") {
			if !slices.Contains(hostList, host) {
				hostList = append(hostList, host)
			}
		}
	}
	// iterate over the list of hostnames again.
	// if one contains an FQDN, see whether it can be covered by a wildcard hostname
	// that already exists and skip adding it.
	for _, host := range hostnames {
		if strings.Contains(host, ".") && !strings.HasPrefix(host, "*.") {
			fullHostname := strings.Split(host, ".")
			_, wildcardDomain := fullHostname[0], fmt.Sprintf("*.%s", strings.Join(fullHostname[1:], "."))
			if slices.Contains(hostList, wildcardDomain) {
				log.Debugf("Not adding %s because it is already covered by %s", host, wildcardDomain)
				continue
			}
		}
		if !slices.Contains(hostList, host) {
			log.Debugf("Adding %s to hostList", host)
			hostList = append(hostList, host)
		}
	}
	sort.Strings(hostList)

	// write strings to subkey
	mustWriteStrings(registryKey, "MatchHosts", hostList)
	mustWriteString(registryKey, "PublicKey", publicKey)

	return true, nil
}

// formatLocalCommandString replaces placeholders in a constant with actual values
func formatLocalCommandString(tshPath string, cluster string) string {
	// replace the placeholder "%cluster" with the actual cluster name as passed to the function
	clusterString := strings.ReplaceAll(puttyProxyTelnetCommand, "%cluster", cluster)
	// PuTTY needs its paths to be double-escaped i.e. C:\\Users\\User\\tsh.exe
	escapedTshPath := strings.ReplaceAll(tshPath, `\`, `\\`)
	return strings.ReplaceAll(clusterString, "%tsh", escapedTshPath)
}

// onPuttyConfig handles the `tsh config putty` subcommand
func onPuttyConfig(cf *CLIConf) error {
	if runtime.GOOS != constants.WindowsOS {
		return trace.NotImplemented("PuTTY config is only implemented on Windows")
	}

	tc, err := makeClient(cf, true)
	if err != nil {
		return trace.Wrap(err)
	}

	// parse out proxy details
	proxyHost, proxyPort, err := net.SplitHostPort(tc.Config.SSHProxyAddr)
	if err != nil {
		return trace.Wrap(err)
	}

	// get the public key of the Teleport host CA so we can add it to PuTTY's list of trusted keys
	var caPublicKey string
	err = tc.WithRootClusterClient(cf.Context, func(clt auth.ClientI) error {
		caPublicKey, err = client.ExportAuthorities(cf.Context, clt, client.ExportAuthoritiesRequest{AuthType: "host"})
		if err != nil {
			return trace.Wrap(err)
		}
		return nil
	})
	_, _, pubKey, _, _, err := ssh.ParseKnownHosts([]byte(caPublicKey))
	if err != nil {
		return trace.Wrap(err)
	}
	publicKey := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pubKey)), "\n")

	// connect to proxy to fetch cluster info
	proxyClient, err := tc.ConnectToProxy(cf.Context)
	if err != nil {
		return trace.Wrap(err)
	}
	defer proxyClient.Close()

	// get root cluster name
	rootClusterName, rootErr := proxyClient.RootClusterName(cf.Context)
	// TODO(gus): figure out what to do (if anything) about leaf clusters
	//leafClusters, leafErr := proxyClient.GetLeafClusters(cf.Context)
	_, leafErr := proxyClient.GetLeafClusters(cf.Context)
	if err := trace.NewAggregate(rootErr, leafErr); err != nil {
		return trace.Wrap(err)
	}

	keysDir := profile.FullProfilePath(tc.Config.KeysDir)
	ppkFilePath := keypaths.PPKFilePath(keysDir, proxyHost, tc.Config.Username)
	certificateFilePath := keypaths.SSHCertPath(keysDir, proxyHost, tc.Config.Username, rootClusterName)

	proxyHostname := proxyHost
	hostname := tc.Config.Host
	userHostString := hostname
	login := ""
	if tc.Config.HostLogin != "" {
		login = tc.Config.HostLogin
		userHostString = fmt.Sprintf("%v@%v", login, userHostString)
	}

	// format local command string (to run 'tsh proxy ssh')
	localCommandString := formatLocalCommandString(cf.executablePath, rootClusterName)

	// add proxied session to registry
	if ok, err := addPuTTYSession(proxyHostname, hostname, login, proxyPort, ppkFilePath, certificateFilePath, localCommandString); !ok {
		log.Fatalf("Failed to add proxied PuTTY session for %v: %T", userHostString, err)
		return trace.Wrap(err)
	} else {
		fmt.Printf("Added PuTTY session for %v (via %v)", userHostString, proxyHostname)
	}

	// add root session to registry
	if ok, err := addPuTTYSession("-", proxyHostname, login, proxyPort, ppkFilePath, certificateFilePath, localCommandString); !ok {
		log.Fatalf("Failed to add PuTTY session for %v: %T", proxyHostname, err)
		return trace.Wrap(err)
	} else {
		log.Debugf("Added root PuTTY session for %v", proxyHostname)
	}

	keyTitle := fmt.Sprintf(`teleportHostCA-%v`, proxyHostname)
	wildcardProxyHostname := fmt.Sprintf(`*.%v`, proxyHostname)
	wildcardRootClusterName := fmt.Sprintf(`*.%v`, rootClusterName)
	hostnameList := []string{proxyHostname, wildcardProxyHostname, hostname, rootClusterName, wildcardRootClusterName}
	if ok, err := addHostCAPublicKey(keyTitle, publicKey, hostnameList); !ok {
		log.Fatalf("Failed to add host CA key: %T", err)
		return trace.Wrap(err)
	} else {
		log.Debugf("Added/updated host CA key for %v", proxyHostname)
	}

	return nil
}
