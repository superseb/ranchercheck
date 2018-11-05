package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type setting struct {
	Value string `json:"value"`
}

func certinfo(cert *x509.Certificate) {
	fmt.Printf("\tSubject: %+v\n", cert.Subject)
	fmt.Printf("\tIssuer: %+v\n", cert.Issuer)
	fmt.Printf("\tIsCA: %+v\n", cert.IsCA)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("\tDNS Names: %+v\n", cert.DNSNames)
	} else {
		fmt.Println("\tDNS Names: <none>")
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Printf("\tIPAddresses: %+v\n", cert.IPAddresses)
	} else {
		fmt.Println("\tIPAddresses: <none>")
	}
	fmt.Printf("\tNotBefore: %+v\n", cert.NotBefore)
	fmt.Printf("\tNotAfter: %+v\n", cert.NotAfter)
	fmt.Printf("\tSignatureAlgorithm: %+v\n", cert.SignatureAlgorithm)
	fmt.Printf("\tPublicKeyAlgorithm: %+v\n", cert.PublicKeyAlgorithm)
}

func main() {
	givenUrl := os.Args[1]
	pingUrl := givenUrl + "/ping"
	cacertsUrl := givenUrl + "/v3/settings/cacerts"

	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	pong := []byte("pong")
	ping, err := insecureClient.Get(pingUrl)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pingbody, err := ioutil.ReadAll(ping.Body)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if !bytes.Equal(pingbody, pong) {
		fmt.Printf("Does not look like a Rancher 2.x API, response from %s is not 'pong', received response:\n%s\n", pingUrl, string(pingbody))
		os.Exit(1)
	}

	res, err := insecureClient.Get(cacertsUrl)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}

	cacertssetting := setting{}
	jsonErr := json.Unmarshal(body, &cacertssetting)
	if jsonErr != nil {
		fmt.Println(jsonErr)
	}

	caCertPool, _ := x509.SystemCertPool()

	if len(cacertssetting.Value) > 0 {
		cacertsbyte := []byte(cacertssetting.Value)
		var blocks [][]byte
		for {
			var certDERBlock *pem.Block
			certDERBlock, cacertsbyte = pem.Decode(cacertsbyte)
			if certDERBlock == nil {
				break
			}

			if certDERBlock.Type == "CERTIFICATE" {
				blocks = append(blocks, certDERBlock.Bytes)
			}
		}
		if len(blocks) > 1 {
			fmt.Printf("Found %d certificates at %s, should be 1\n", len(blocks), cacertsUrl)
		}
		fmt.Printf("Certificate details from %s\n", cacertsUrl)

		blockcount := 0
		for _, block := range blocks {
			cert, err := x509.ParseCertificate(block)
			if err != nil {
				log.Println(err)
				continue
			}

			fmt.Printf("Certificate #%d (%s)\n", blockcount, cacertsUrl)
			certinfo(cert)

			blockcount = blockcount + 1
		}
		caCertPool.AppendCertsFromPEM([]byte(cacertssetting.Value))
	} else {
		fmt.Printf("No value configured at %s, assuming certificate signed by trusted CA\n", cacertsUrl)
	}

	if res.TLS != nil && len(res.TLS.PeerCertificates) > 0 {
		fmt.Printf("Certificate details from %s\n", givenUrl)
		var previouscert *x509.Certificate
		for i := range res.TLS.PeerCertificates {
			cert := res.TLS.PeerCertificates[i]
			fmt.Printf("Certificate #%d (%s)\n", i, givenUrl)
			certinfo(cert)
			if i > 0 {
				if previouscert.Issuer.String() != cert.Subject.String() {
					fmt.Printf("Certficate's Subject (%s) does not match with previous certificate Issuer (%s)", cert.Subject.String(), previouscert.Issuer.String())
				}
			}
			previouscert = cert
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	_, err = client.Get(givenUrl)

	if err != nil {
		if strings.Contains(err.Error(), "certificate signed by unknown authority") {
			fmt.Printf("Certificate chain is not complete, error: %s\n", err)
		} else {
			fmt.Println(err)
		}
		os.Exit(1)
	}

	fmt.Printf("Certificate chain is complete, connection to %s established successfully\n", givenUrl)
}
