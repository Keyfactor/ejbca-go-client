package ejbca

import "testing"

func TestClient_GetCACertificatePEM(t *testing.T) {
	ejbcaTestPreCheck(t)
}

func TestClient_GetCRLByIssuerDn(t *testing.T) {
	ejbcaTestPreCheck(t)
}

func TestClient_GetV1CAStatus(t *testing.T) {
	ejbcaTestPreCheck(t)
}

func TestClient_GetEJBCACAList(t *testing.T) {
	ejbcaTestPreCheck(t)
}
