package ejbca

import (
	"math/rand"
	"os"
	"testing"
	"time"
)

var client *Client

func ejbcaTestPreCheck(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	if client == nil {
		config := &Config{
			CertificateFile: os.Getenv("EJBCA_CERTPATH"),
			CAFile:          os.Getenv("EJBCA_CAPATH"),
			KeyPassword:     os.Getenv("EJBCA_KEYPASSWORD"),
		}

		var err error
		factory := ClientFactory(os.Getenv("EJBCA_HOSTNAME"), config)
		client, err = factory.NewEJBCAClient()
		if err != nil {
			t.Fatal(err)
		}
		_, err = factory.NewESTClient(os.Getenv("EJBCA_USERNAME"), os.Getenv("EJBCA_PASSWORD"))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientFactory(t *testing.T) {
	config := &Config{
		CertificateFile: os.Getenv("EJBCA_CERTPATH"),
		CAFile:          os.Getenv("EJBCA_CAPATH"),
		KeyPassword:     os.Getenv("EJBCA_KEYPASSWORD"),
	}

	factory := ClientFactory(os.Getenv("EJBCA_HOSTNAME"), config)
	client, err := factory.NewESTClient(os.Getenv("EJBCA_USERNAME"), os.Getenv("EJBCA_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetEJBCACAList()
	if err == nil {
		t.Fatal("Accessing unallocated resources not allowed.")
	} else {
		t.Logf("Client failed where it should have - %s", err.Error())
	}
	_, err = client.EST.CaCerts(os.Getenv("EST_ALIAS"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.NewEJBCAClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetEJBCACAList()
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewEJBCAClient(t *testing.T) {
	config := &Config{
		CertificateFile: os.Getenv("EJBCA_CERTPATH"),
		CAFile:          os.Getenv("EJBCA_CAPATH"),
		KeyPassword:     os.Getenv("EJBCA_KEYPASSWORD"),
	}

	var err error
	factory := ClientFactory(os.Getenv("EJBCA_HOSTNAME"), config)
	client, err = factory.NewEJBCAClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory.NewESTClient(os.Getenv("EJBCA_USERNAME"), os.Getenv("EJBCA_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	// if we get here we passed
}

// From https://github.com/hashicorp/terraform-plugin-sdk/blob/v2.10.0/helper/acctest/random.go#L51
func randStringFromCharSet(strlen int) string {
	charSet := "abcdefghijklmnopqrstuvwxyz012346789"
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = charSet[rand.Intn(len(charSet))]
	}
	return string(result)
}

func getEJBCAEntityConfig(t *testing.T) string {
	var endentity string
	if endentity = os.Getenv("EJBCA_ENDENTITY"); endentity == "" {
		t.Fatal("EJBCA_ENDENTITY must be set")
	}
	return endentity
}
