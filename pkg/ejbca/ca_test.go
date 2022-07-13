package ejbca

import "testing"

func TestClient_GetCACertificate(t *testing.T) {
	ejbcaTestPreCheck(t)

	cAs, err := client.GetEJBCACAList()
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := client.GetCACertificate(cAs.CertificateAuthorities[0].SubjectDn)
	if err != nil {
		return
	}

	t.Logf("CA certificate with subject DN %s has thumbprint %d", cAs.CertificateAuthorities[0].SubjectDn, certificate[0].SerialNumber)
}

func TestClient_GetCRLByIssuerDn(t *testing.T) {
	ejbcaTestPreCheck(t)

	cAs, err := client.GetEJBCACAList()
	if err != nil {
		t.Fatal(err)
	}

	crl, err := client.GetCRLByIssuerDn(cAs.CertificateAuthorities[0].IssuerDn)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%s's CRL: %v", cAs.CertificateAuthorities[0].IssuerDn, crl.CRL)
}

func TestClient_GetV1CAStatus(t *testing.T) {
	ejbcaTestPreCheck(t)

	status, err := client.GetV1CAStatus()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("V1 CA endpoint has status %s, version %s, and revision %s", status.Status, status.Version, status.Revision)
}

func TestClient_GetEJBCACAList(t *testing.T) {
	ejbcaTestPreCheck(t)

	list, err := client.GetEJBCACAList()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Found %d CAs", len(list.CertificateAuthorities))
}
