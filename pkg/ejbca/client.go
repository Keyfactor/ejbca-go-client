package ejbca

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

func ClientFactory(hostname string, config *Config) *SharedClientFactory {
	f := new(SharedClientFactory)
	if hostname == "" {
		log.Println("[ERROR] Hostname is required to create a client factory.")
		return nil
	}
	f.hostname = hostname
	f.config = config
	return f
}

func (f *SharedClientFactory) NewEJBCAClient() (*Client, error) {
	log.Println("[INFO] Building new EJBCA client")
	err := f.loginToEJBCAREST()
	if err != nil {
		return nil, err
	}

	// Sanity check - client should not be nil
	if f.client == nil {
		return nil, fmt.Errorf("something went wrong. failed to create new rest client")
	}

	// Allow users to configure default CA, end entity profile, and certificate profile to simplify
	// calling the client
	if f.config != nil {
		f.client.defaultCertificateAuthorityName = f.config.DefaultCertificateAuthorityName
		f.client.defaultCertificateProfileName = f.config.DefaultCertificateProfileName
		f.client.defaultEndEntityProfileName = f.config.DefaultEndEntityProfileName
	}
	return f.client, nil
}

func (f *SharedClientFactory) NewESTClient(username string, password string) (*Client, error) {
	log.Println("[INFO] Building new EJBCA EST client")
	err := f.loginToEJBCAEST(username, password)
	if err != nil {
		return nil, err
	}

	// Sanity check - EST should not be nil.
	if f.client.EST == nil {
		return nil, fmt.Errorf("something went wrong. failed to create new est client")
	}

	if f.config != nil {
		f.client.EST.defaultESTAlias = f.config.DefaultESTAlias
	}

	return f.client, nil
}

func (f *SharedClientFactory) loginToEJBCAREST() error {
	if f.hostname == "" {
		return errors.New("ejbca hostname required for creation of new client")
	}

	if f.client == nil {
		f.client = new(Client)
	}

	httpClient, err := buildHTTPClient(f.config)
	if err != nil {
		return err
	}

	f.client.hostname = f.hostname
	f.client.httpRESTClient = httpClient

	f.client.configured = true
	status, err := f.client.GetV1CertificateStatus()
	if err != nil {
		return err
	}
	log.Printf("[INFO] Connected to instance %s with status %s", status.Revision, status.Status)

	return nil
}

// buildBasicAuthString constructs a basic authorization string necessary for basic authorization to Keyfactor. It
// returns a base-64 encoded auth string including the 'Basic ' prefix.
func buildBasicAuthString(username string, password string) string {
	authString := strings.Join([]string{username, ":", password}, "")
	authBytes := []byte(authString)
	authDigest := base64.StdEncoding.EncodeToString(authBytes)
	authField := strings.Join([]string{"Basic ", authDigest}, "")
	return authField
}

func (f *SharedClientFactory) loginToEJBCAEST(username string, password string) error {
	if username == "" {
		return errors.New("ejbca username required to create est client")
	}
	if password == "" {
		return errors.New("ejbca password required to create est client")
	}
	if f.hostname == "" {
		return errors.New("ejbca hostname required for creation of new client")
	}

	// If there is no client configured, create one.
	// User can choose to later configure the regular REST client using the same client factory
	if f.client == nil {
		f.client = new(Client)
		f.client.configured = false
	}
	est := new(ESTClient)
	est.hostname = f.hostname

	// Build HTTP transport with optional configuration of client certificate.
	httpClient, err := buildEstHTTPClient(f.config)
	if err != nil {
		return err
	}
	est.httpESTClient = httpClient

	// Build basic authentication string for later use
	est.basicAuth = buildBasicAuthString(username, password)

	/*
		_, err = est.CaCerts("")
		if err != nil {
			return err
		} */

	f.client.EST = est
	return nil
}

func buildHTTPClient(config *Config) (*http.Client, error) {
	cert, err := findClientCertificate(config)
	if err != nil {
		return nil, err
	}

	// Configure new TLS object
	tlsConfig := &tls.Config{
		Certificates:  []tls.Certificate{*cert},
		Renegotiation: tls.RenegotiateOnceAsClient,
	}

	if config.CAFile != "" {
		err = addCAToPool(tlsConfig, config.CAFile)
		if err != nil {
			return nil, err
		}
	}

	// Configure HTTP transports with TLS config
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Build new HTTP object to communicate with EJBCA
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	return httpClient, nil
}

func addCAToPool(tls *tls.Config, caPath string) error {
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to create cert pool from ca cert at path %s", caPath)
	}
	tls.RootCAs = pool
	log.Printf("[DEBUG] Added CA certificate from %s to HTTP transport trusted CA pool", caPath)

	return nil
}

func buildEstHTTPClient(config *Config) (*http.Client, error) {
	// Configure new TLS object
	tlsConfig := new(tls.Config)
	tlsConfig.Renegotiation = tls.RenegotiateOnceAsClient

	// If the client certificate file path was specified, search for the certificate.
	if config.CertificateFile != "" {
		cert, err := findClientCertificate(config)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	// If a CA was provided, add it to the trusted CA pool
	if config.CAFile != "" {
		err := addCAToPool(tlsConfig, config.CAFile)
		if err != nil {
			return nil, err
		}
	}

	// Configure HTTP transports with TLS config
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Build new HTTP object to communicate with EJBCA
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	return httpClient, nil
}

func findClientCertificate(config *Config) (*tls.Certificate, error) {
	// Load client certificate
	var cert tls.Certificate

	if config.CertificateFile == "" {
		return nil, fmt.Errorf("path to client certificate is required")
	}

	// Read and parse the passed certificate file which could contain the certificate and private key
	log.Printf("[TRACE] Reading client certificate from %s", config.CertificateFile)
	buf, err := ioutil.ReadFile(config.CertificateFile)
	if err != nil {
		return nil, err
	}
	certificates, privKey, err := decodePEMBytes(buf, config.KeyPassword)
	if err != nil {
		return nil, err
	}
	if len(privKey) <= 0 {
		// if no private key was found, see if a path was specified to a private key
		if config.KeyFile == "" {
			return nil, fmt.Errorf("no private key found in %s and no path to a private key specified", config.CertificateFile)
		}
		log.Printf("Didn't find private key in client certificate file, looking in %s", config.KeyFile)
		buf, err = ioutil.ReadFile(config.KeyFile)
		if err != nil {
			return nil, err
		}
		_, privKey, err = decodePEMBytes(buf, config.KeyPassword)
		if err != nil {
			return nil, err
		}
		if len(privKey) <= 0 {
			return nil, fmt.Errorf("didn't find private key in path %s", config.KeyFile)
		}
	}
	if len(certificates) <= 0 {
		return nil, fmt.Errorf("didn't find certificate in file at path %s", config.CertificateFile)
	}
	cert, err = tls.X509KeyPair(pem.EncodeToMemory(certificates[0]), privKey)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Found client certificate and private key")

	return &cert, nil
}

func decodePEMBytes(buf []byte, privKeyPassword string) ([]*pem.Block, []byte, error) {
	var privKey []byte
	var err error
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			if x509.IsEncryptedPEMBlock(block) {
				if privKeyPassword == "" {
					return nil, nil, fmt.Errorf("found encrypted private key but no password was provided")
				}
				privKey, err = x509.DecryptPEMBlock(block, []byte(privKeyPassword))
				if err != nil {
					return nil, nil, err
				}
				log.Println("[TRACE] Decrypted private key")
				privKey = pem.EncodeToMemory(&pem.Block{
					Type:  block.Type,
					Bytes: privKey,
				})
			} else {
				log.Println("[TRACE] Private key is not protected")
				privKey = pem.EncodeToMemory(block)
			}
		} else {
			certificates = append(certificates, block)
		}
		log.Printf("[TRACE] Found %s", block.Type)
	}
	return certificates, privKey, nil
}

// SendRequest takes an APIRequest struct as input and generates an API call
// using the configuration data inside. It returns a pointer to a http response
// struct and an error, if applicable.
func (c *RESTClient) sendRESTRequest(request *request) (*http.Response, error) {
	if !c.configured {
		return nil, fmt.Errorf("rest client is not configured. ensure that NewEJBCAClient was called from the client factory")
	}

	u, err := url.Parse(c.hostname) // Parse raw hostname into URL structure
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		u.Scheme = "https"
	}
	endpoint := "ejbca/ejbca-rest-api/" + request.Endpoint
	u.Path = path.Join(u.Path, endpoint)

	// Set request query
	if request.Query != nil {
		queryString := u.Query()
		for query, value := range request.Query {
			queryString.Set(query, value)
		}
		u.RawQuery = queryString.Encode()
	}

	ejbcaPath := u.String() // Convert absolute path to string

	log.Printf("[INFO] Preparing a %s request to path '%s'", request.Method, ejbcaPath)
	jsonByes, err := json.Marshal(request.Payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(request.Method, ejbcaPath, bytes.NewBuffer(jsonByes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Set custom EJBCA headers
	if request.Headers != nil {
		for header, value := range request.Headers {
			req.Header.Set(header, value)
		}
	}

	resp, err := c.httpRESTClient.Do(req)
	if err != nil {
		return nil, err
	}

	err = evaluateHttpResp(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (e *ESTClient) sendESTRequest(request *request) (*http.Response, error) {
	u, err := url.Parse(e.hostname) // Parse raw hostname into URL structure
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		u.Scheme = "https"
	}
	endpoint := "/.well-known/est/" + request.Endpoint
	u.Path = path.Join(u.Path, endpoint)

	ejbcaPath := u.String() // Convert absolute path to string

	// Set request query
	if request.Query != nil {
		queryString := u.Query()
		for query, value := range request.Query {
			queryString.Set(query, value)
		}
		u.RawQuery = queryString.Encode()
	}

	var buf *strings.Reader
	if request.Payload != nil {
		buf = strings.NewReader(request.Payload.(string))
	} else {
		buf = strings.NewReader("")
	}

	req, err := http.NewRequest(request.Method, ejbcaPath, buf)
	if err != nil {
		return nil, err
	}

	// Set custom EST headers
	if request.Headers != nil {
		for header, value := range request.Headers {
			req.Header.Set(header, value)
		}
	}

	log.Printf("[TRACE] Prepared a %s request to %s://%s%s", req.Method, req.URL.Scheme, req.URL.Host, req.URL.RequestURI())

	// Set authorization
	req.Header.Set("Authorization", e.basicAuth)

	resp, err := e.httpESTClient.Do(req)
	if err != nil {
		return nil, err
	}

	err = evaluateHttpResp(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func evaluateHttpResp(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusCreated {
		log.Printf("[DEBUG] %s succeeded with response code %d", resp.Request.Method, resp.StatusCode)
		return nil
	} else {
		var stringMessage string
		content, ok := resp.Header["Content-Type"]
		if ok && strings.Contains(content[0], "json") {
			var errorMessage interface{} // Decode JSON body to handle issue
			err := json.NewDecoder(resp.Body).Decode(&errorMessage)
			if err != nil {
				return err
			}
			str, ok := errorMessage.(map[string]interface{})["error_message"]
			message := "[ERROR] Request failed with code %d and message "
			if ok {
				message = fmt.Sprintf(message+"'%s'", resp.StatusCode, str.(string))
			} else {
				message = fmt.Sprintf(message+"%v", errorMessage)
			}
			log.Printf(message)
			stringMessage = fmt.Sprintf("%v", errorMessage)
		} else {
			log.Printf("[ERROR] Call to %s returned status %s.", resp.Request.URL.Host, resp.Status)
			encoded, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			stringMessage = string(encoded)
		}

		return fmt.Errorf(stringMessage)
	}
}
