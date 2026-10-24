package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	handler "github.com/group-project/authentication/internal/handler/http"
	"github.com/group-project/authentication/internal/repository/postgres"
	"github.com/group-project/authentication/internal/router"
	"github.com/group-project/authentication/internal/service"
	"github.com/rs/zerolog"
)

// Test-only subprocess host. Bootstrap secrets travel over the parent's private
// stdout pipe, never test logs or command arguments. Not part of any server build.
func TestStockE2EAuthHost(t *testing.T) {
	if os.Getenv("STOCK_E2E_HOST") != "1" {
		t.Skip("requires isolated parent harness")
	}
	pool := machinePool(t)
	gin.SetMode(gin.ReleaseMode)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("fixture key")
	}
	s, err := service.NewMachineService(postgres.NewMachineRepository(pool), key, "erp-auth", 5*time.Minute)
	if err != nil {
		t.Fatal("fixture service")
	}
	id, err := s.Create(ctx)
	if err != nil {
		t.Fatal("fixture identity")
	}
	if s.SetEnabled(ctx, id, true) != nil || s.SetGrant(ctx, id, true) != nil {
		t.Fatal("fixture grant")
	}
	credential, err := s.Rotate(ctx, id, time.Hour)
	if err != nil {
		t.Fatal("fixture credential")
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "isolated Auth"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture certificate")
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("fixture public key")
	}
	server := httptest.NewUnstartedServer(router.NewRouter(nil, nil, nil, pool).WithMachineHandler(handler.NewMachineHandler(s, zerolog.Nop())).Router())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	bootstrap := struct{ URL, CA, PublicKey, Client, Credential string }{server.URL + "/api/v1/auth/service-token", string(ca), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})), id.String(), credential.Secret}
	if json.NewEncoder(os.Stdout).Encode(bootstrap) != nil {
		t.Fatal("fixture pipe")
	}
	decoder := json.NewDecoder(os.Stdin)
	for {
		var command string
		if decoder.Decode(&command) != nil || command == "stop" {
			break
		}
		switch command {
		case "revoke":
			if s.Revoke(ctx, id, credential.ID) != nil {
				t.Fatal("fixture revoke")
			}
		case "disable":
			if s.SetEnabled(ctx, id, false) != nil {
				t.Fatal("fixture disable")
			}
		default:
			t.Fatal("unknown fixture command")
		}
		if json.NewEncoder(os.Stdout).Encode(true) != nil {
			t.Fatal("fixture acknowledgement")
		}
	}
}
