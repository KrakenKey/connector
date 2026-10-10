package api

import (
	"context"
	"net/http"
	"testing"
)

func TestGetCertAwaitingCSR(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":9,"status":"awaiting_csr","crtPem":null,"requestedNames":["api.example.com","www.example.com"],
			"managedBy":"connector","autoRenew":false,"renewAfter":"2026-10-10T14:00:00.000Z"}`))
	})
	cert, err := c.GetCert(context.Background(), 9)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Status != StatusAwaitingCSR || len(cert.RequestedNames) != 2 || cert.CrtPem != "" {
		t.Errorf("cert %+v", cert)
	}
}
