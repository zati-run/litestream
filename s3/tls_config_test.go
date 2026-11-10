package s3

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// emptyListing answers ListObjectsV2 with no objects.
func emptyListing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><Prefix></Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`))
}

// refusals counts TLS handshakes the client refused.
type refusals struct{ n atomic.Int32 }

func (r *refusals) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		r.n.Add(1)
	}
	return len(p), nil
}

func newS3Server(t *testing.T) (*httptest.Server, *refusals) {
	t.Helper()
	r := &refusals{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(emptyListing))
	srv.Config.ErrorLog = log.New(r, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, r
}

// otherCA is a CA that did not issue the test server's certificate.
func otherCA(t *testing.T) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func listOnce(t *testing.T, srv *httptest.Server, cfg *tls.Config, skip bool) error {
	t.Helper()
	// A refused handshake is retried with backoff; the deadline ends it.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := NewReplicaClient()
	c.Bucket, c.Path, c.Region = "bucket", "db", "us-east-1"
	c.Endpoint, c.ForcePathStyle = srv.URL, true
	c.AccessKeyID, c.SecretAccessKey = "AK", "SK"
	c.TLSConfig, c.SkipVerify = cfg, skip
	itr, err := c.LTXFiles(ctx, 0, 0, false)
	if err != nil {
		return err
	}
	defer itr.Close()
	for itr.Next() {
	}
	return itr.Err()
}

func TestReplicaClient_TLSConfig(t *testing.T) {
	srv, refused := newS3Server(t)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	t.Run("RootCAs trusts the endpoint", func(t *testing.T) {
		if err := listOnce(t, srv, &tls.Config{RootCAs: pool}, false); err != nil {
			t.Fatal(err)
		}
	})
	for name, cfg := range map[string]*tls.Config{
		"without it the endpoint is refused": nil,
		"another CA is refused":              {RootCAs: otherCA(t)},
	} {
		t.Run(name, func(t *testing.T) {
			before := refused.n.Load()
			if err := listOnce(t, srv, cfg, false); err == nil {
				t.Fatal("the endpoint was trusted")
			}
			if refused.n.Load() == before {
				t.Fatal("no handshake was refused; the failure was something else")
			}
		})
	}
	t.Run("SkipVerify still applies", func(t *testing.T) {
		if err := listOnce(t, srv, &tls.Config{RootCAs: otherCA(t)}, true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the caller's config is not modified", func(t *testing.T) {
		cfg := &tls.Config{RootCAs: pool}
		if err := listOnce(t, srv, cfg, true); err != nil {
			t.Fatal(err)
		}
		if cfg.InsecureSkipVerify {
			t.Fatal("Init changed the caller's TLSConfig")
		}
	})
}
