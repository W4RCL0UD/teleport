// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type privKey struct {
	signer       ssh.Signer
	cryptoSigner crypto.Signer
	comment      string
	expire       *time.Time
}

type keyring struct {
	mu   sync.Mutex
	keys []privKey

	locked     bool
	passphrase []byte
}

var (
	errLocked   = trace.AccessDenied("agent: locked")
	errNotFound = trace.NotFound("agent: key not found")
)

// NewKeyring returns an Agent that holds keys in memory.  It is safe
// for concurrent use by multiple goroutines.
func NewKeyring() agent.Agent {
	return &keyring{}
}

// RemoveAll removes all identities.
func (r *keyring) RemoveAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	r.keys = nil
	return nil
}

// removeLocked does the actual key removal. The caller must already be holding the
// keyring mutex.
func (r *keyring) removeLocked(want []byte) error {
	found := false
	for i := 0; i < len(r.keys); {
		if bytes.Equal(r.keys[i].signer.PublicKey().Marshal(), want) {
			found = true
			r.keys[i] = r.keys[len(r.keys)-1]
			r.keys = r.keys[:len(r.keys)-1]
			continue
		} else {
			i++
		}
	}

	if !found {
		return errNotFound
	}
	return nil
}

// Remove removes all identities with the given public key.
func (r *keyring) Remove(key ssh.PublicKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	return r.removeLocked(key.Marshal())
}

// Lock locks the agent. Sign and Remove will fail, and List will return an empty list.
func (r *keyring) Lock(passphrase []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	r.locked = true
	r.passphrase = passphrase
	return nil
}

// Unlock undoes the effect of Lock
func (r *keyring) Unlock(passphrase []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.locked {
		return errors.New("agent: not locked")
	}
	if subtle.ConstantTimeCompare(passphrase, r.passphrase) != 1 {
		return fmt.Errorf("agent: incorrect passphrase")
	}

	r.locked = false
	r.passphrase = nil
	return nil
}

// expireKeysLocked removes expired keys from the keyring. If a key was added
// with a lifetimesecs contraint and seconds >= lifetimesecs seconds have
// elapsed, it is removed. The caller *must* be holding the keyring mutex.
func (r *keyring) expireKeysLocked() {
	for _, k := range r.keys {
		if k.expire != nil && time.Now().After(*k.expire) {
			r.removeLocked(k.signer.PublicKey().Marshal())
		}
	}
}

// List returns the identities known to the agent.
func (r *keyring) List() ([]*agent.Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		// section 2.7: locked agents return empty.
		return nil, nil
	}

	r.expireKeysLocked()
	var ids []*agent.Key
	for _, k := range r.keys {
		pub := k.signer.PublicKey()
		ids = append(ids, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment})
	}
	return ids, nil
}

// Insert adds a private key to the keyring. If a certificate
// is given, that certificate is added as public key. Note that
// any constraints given are ignored.
func (r *keyring) Add(key agent.AddedKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	cryptoSigner, ok := key.PrivateKey.(crypto.Signer)
	if !ok {
		return trace.BadParameter("invalid agent key: signer of type %T does not implement crypto.Signer", cryptoSigner)
	}

	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return err
	}

	if cert := key.Certificate; cert != nil {
		signer, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			return err
		}
	}

	p := privKey{
		signer:       signer,
		cryptoSigner: cryptoSigner,
		comment:      key.Comment,
	}

	if key.LifetimeSecs > 0 {
		t := time.Now().Add(time.Duration(key.LifetimeSecs) * time.Second)
		p.expire = &t
	}

	r.keys = append(r.keys, p)

	return nil
}

// Sign returns a signature for the data.
func (r *keyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.SignWithFlags(key, data, 0)
}

func (r *keyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, errLocked
	}

	r.expireKeysLocked()
	wanted := key.Marshal()
	for _, k := range r.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			if flags == 0 {
				return k.signer.Sign(rand.Reader, data)
			} else {
				if algorithmSigner, ok := k.signer.(ssh.AlgorithmSigner); !ok {
					return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", k.signer)
				} else {
					var algorithm string
					switch flags {
					case agent.SignatureFlagRsaSha256:
						algorithm = ssh.KeyAlgoRSASHA256
					case agent.SignatureFlagRsaSha512:
						algorithm = ssh.KeyAlgoRSASHA512
					default:
						return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
					}
					return algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
				}
			}
		}
	}
	return nil, errNotFound
}

// Signers returns signers for all the known keys.
func (r *keyring) Signers() ([]ssh.Signer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, errLocked
	}

	r.expireKeysLocked()
	s := make([]ssh.Signer, 0, len(r.keys))
	for _, k := range r.keys {
		s = append(s, k.signer)
	}
	return s, nil
}

// Sign returns a signature for the data.
func (r *keyring) SignPKCS7(key ssh.PublicKey, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, errLocked
	}

	r.expireKeysLocked()
	wanted := key.Marshal()
	for _, k := range r.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			return k.cryptoSigner.Sign(rand.Reader, digest, opts)
		}
	}
	return nil, errNotFound
}

func (r *keyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	switch extensionType {
	case agentExtensionSignPKCS7:
		var req signPKCS7Request
		if err := ssh.Unmarshal(contents, &req); err != nil {
			return nil, trace.Wrap(err)
		}

		sshPub, err := ssh.ParsePublicKey(req.KeyBlob)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		hash := crypto.Hash(req.CryptoHash)
		var signerOpts crypto.SignerOpts = hash
		if req.UsePSS {
			signerOpts = &rsa.PSSOptions{
				SaltLength: int(req.PSSSaltLength),
				Hash:       hash,
			}
		}

		signature, err := r.SignPKCS7(sshPub, req.Digest, signerOpts)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return ssh.Marshal(ssh.Signature{
			Format: sshPub.Type(),
			Blob:   signature,
		}), nil
	default:
		return nil, agent.ErrExtensionUnsupported
	}
}

// agentExtesionSignPKCS7 extension performs a signature according to
// PKCS#7 specification.
const agentExtensionSignPKCS7 = "sign-pkcs7@goteleport.com"

type signPKCS7Request struct {
	KeyBlob       []byte
	Digest        []byte
	CryptoHash    uint32
	UsePSS        bool
	PSSSaltLength uint32
}

func SignPKCS7Extension(agent agent.ExtendedAgent, pub ssh.PublicKey, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	req := signPKCS7Request{
		KeyBlob:    pub.Marshal(),
		Digest:     digest,
		CryptoHash: uint32(opts.HashFunc()),
	}
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		req.UsePSS = true
		switch pssOpts.SaltLength {
		case rsa.PSSSaltLengthEqualsHash:
			req.PSSSaltLength = uint32(opts.HashFunc().Size())
		default:
			req.PSSSaltLength = uint32(pssOpts.SaltLength)
		}
	}
	respBlob, err := agent.Extension(agentExtensionSignPKCS7, ssh.Marshal(req))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var resp ssh.Signature
	if err := ssh.Unmarshal(respBlob, &resp); err != nil {
		return nil, trace.Wrap(err)
	}
	return resp.Blob, nil
}
