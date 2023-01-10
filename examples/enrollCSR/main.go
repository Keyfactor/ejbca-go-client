package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "github.com/Keyfactor/ejbca-go-client/pkg/ejbca"
    "log"
    "math/big"
    "os"
)

func main() {
    config := &ejbca.Config{
        CertificateFile: os.Getenv("EJBCA_CERTPATH"),
        CAFile:          os.Getenv("EJBCA_CAPATH"),
        KeyPassword:     os.Getenv("EJBCA_KEYPASSWORD"),
    }
    factory := ejbca.ClientFactory(os.Getenv("EJBCA_HOSTNAME"), config)
    client, err := factory.NewESTClient(os.Getenv("USERNAME"), os.Getenv("PASSWORD"))
    if err != nil {
        log.Fatal(err)
    }

    _, err = client.EST.CaCerts("clienthttp")
    if err != nil {
        log.Fatal(err)
    }
    csr := generateCSR("goESTTest1-"+randStringFromCharSet(10), "Administrators", "Internal Test", "US")
    encoded := base64.StdEncoding.EncodeToString(csr)

    _, err = client.EST.SimpleEnroll("hayden", encoded)
    if err != nil {
        log.Fatal(err)
    }
}

func generateCSR(commonName string, ou string, o string, country string) []byte {
    keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

    subj := pkix.Name{
        CommonName: commonName,
    }
    if ou != "" {
        subj.OrganizationalUnit = []string{ou}
    }
    if o != "" {
        subj.Organization = []string{o}
    }
    if country != "" {
        subj.Country = []string{country}
    }

    template := x509.CertificateRequest{
        Subject:            subj,
        SignatureAlgorithm: x509.SHA256WithRSA,
    }
    csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
    /*
    	var csrBuf bytes.Buffer
    	err := pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
    	if err != nil {
    		return ""
    	}
    */

    return csrBytes
}

// From https://github.com/hashicorp/terraform-plugin-sdk/blob/v2.10.0/helper/acctest/random.go#L51
func randStringFromCharSet(strlen int) string {
    charSet := "abcdefghijklmnopqrstuvwxyz012346789"
    result := make([]byte, strlen)
    for i := 0; i < strlen; i++ {
        num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
        if err != nil {
            return ""
        }
        result[i] = charSet[num.Int64()]
    }
    return string(result)
}
