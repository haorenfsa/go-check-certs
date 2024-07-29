// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/haorenfsa/gocheck-certs/pkg"
)

const defaultConcurrency = 8

const (
	errExpiringShortly = `[WARNING!!!!!!!!!!!!!!!!] 
domain %s
cert: %s
expires in %d days
`
	errExpiringSoon = `[INFO] domain: %s
cert: %s 
expires in: %d days
`
	errSunsetAlg = "[WARNING!!!!!!!!!!!!!!!!]\t %s: '%s' expires after the sunset date for its signature algorithm '%s'."
)

type Host struct {
	Addr       string
	ServerName string
}

type sigAlgSunset struct {
	name      string    // Human readable name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}

// sunsetSigAlgs is an algorithm to string mapping for signature algorithms
// which have been or are being deprecated.  See the following links to learn
// more about SHA1's inclusion on this list.
//
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSigAlgs = map[x509.SignatureAlgorithm]sigAlgSunset{
	x509.MD2WithRSA: sigAlgSunset{
		name:      "MD2 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.MD5WithRSA: sigAlgSunset{
		name:      "MD5 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.SHA1WithRSA: sigAlgSunset{
		name:      "SHA1 with RSA",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: sigAlgSunset{
		name:      "DSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: sigAlgSunset{
		name:      "ECDSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

var (
	hostsFile   = flag.String("hosts", "", "The path to the file containing a list of hosts to check.")
	warnYears   = flag.Int("years", 0, "Warn if the certificate will expire within this many years.")
	warnMonths  = flag.Int("months", 0, "Warn if the certificate will expire within this many months.")
	warnDays    = flag.Int("days", 0, "Warn if the certificate will expire within this many days.")
	checkSigAlg = flag.Bool("check-sig-alg", true, "Verify that non-root certificates are using a good signature algorithm.")
	concurrency = flag.Int("concurrency", defaultConcurrency, "Maximum number of hosts to check at once.")
	webhook     = flag.String("webhook", "", "The webhook URL to send the message to.")
)

type certErrors struct {
	commonName string
	errs       []error
}

type hostResult struct {
	host  string
	err   error
	certs []certErrors
}

var alarmer pkg.Alarmer

func main() {
	flag.Parse()

	if len(*hostsFile) == 0 {
		flag.Usage()
		return
	}
	if *warnYears < 0 {
		*warnYears = 0
	}
	if *warnMonths < 0 {
		*warnMonths = 0
	}
	if *warnDays < 0 {
		*warnDays = 0
	}
	if *warnYears == 0 && *warnMonths == 0 && *warnDays == 0 {
		*warnDays = 30
	}
	if *concurrency < 0 {
		*concurrency = defaultConcurrency
	}
	alarmer = pkg.NewLarkWebhookAlarmer(*webhook)
	processHosts()
}

func processHosts() {
	done := make(chan struct{})
	defer close(done)

	hosts := queueHosts(done)
	results := make(chan hostResult)

	var wg sync.WaitGroup
	wg.Add(*concurrency)
	for i := 0; i < *concurrency; i++ {
		go func() {
			processQueue(done, hosts, results)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var msg string = "Certificate check results:\n"
	for r := range results {
		if r.err != nil {
			msg += fmt.Sprintf(`[WARNING!!!!!!!!!!!!!!!!] %s: 
%v
`, r.host, r.err)
			continue
		}
		for _, cert := range r.certs {
			for _, err := range cert.errs {
				msg += fmt.Sprintf("%s\n", err.Error())
			}
		}
	}
	alarmer.Alarm(context.Background(), msg)
}

func queueHosts(done <-chan struct{}) <-chan Host {
	hosts := make(chan Host)
	go func() {
		defer close(hosts)

		fileContents, err := ioutil.ReadFile(*hostsFile)
		if err != nil {
			return
		}
		lines := strings.Split(string(fileContents), "\n")
		for _, line := range lines {
			record := strings.TrimSpace(line)
			if len(record) == 0 || record[0] == '#' {
				continue
			}
			parts := strings.Split(record, " ")
			addrServerName := strings.Split(parts[0], ":")[0]
			host := Host{
				Addr:       parts[0],
				ServerName: addrServerName,
			}
			if len(parts) > 1 {
				host.ServerName = parts[1]
			}
			select {
			case hosts <- host:
			case <-done:
				return
			}
		}
	}()
	return hosts
}

func processQueue(done <-chan struct{}, hosts <-chan Host, results chan<- hostResult) {
	for host := range hosts {
		select {
		case results <- checkHost(host):
		case <-done:
			return
		}
	}
}

func checkHost(host Host) (result hostResult) {
	log.Println("Start checking ", host.ServerName)
	defer log.Println("Done checking ", host.ServerName)
	result = hostResult{
		host:  host.ServerName,
		certs: []certErrors{},
	}
	timeout := 30 * time.Second
	dialer := new(net.Dialer)
	dialer.Timeout = timeout
	dialer.Deadline = time.Now().Add(timeout)
	conn, err := tls.DialWithDialer(dialer, "tcp", host.Addr, &tls.Config{ServerName: host.ServerName})
	if err != nil {
		result.err = err
		return
	}
	defer conn.Close()

	timeNow := time.Now()
	checkedCerts := make(map[string]struct{})
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for certNum, cert := range chain {
			if _, checked := checkedCerts[string(cert.Signature)]; checked {
				continue
			}
			checkedCerts[string(cert.Signature)] = struct{}{}
			cErrs := []error{}

			// Check the expiration.
			if timeNow.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.NotAfter) {
				expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
				if expiresIn <= 24*7 {
					cErrs = append(cErrs, fmt.Errorf(errExpiringShortly, host.ServerName, cert.Subject.CommonName, expiresIn/24))
				} else {
					cErrs = append(cErrs, fmt.Errorf(errExpiringSoon, host.ServerName, cert.Subject.CommonName, expiresIn/24))
				}
			}

			// Check the signature algorithm, ignoring the root certificate.
			if alg, exists := sunsetSigAlgs[cert.SignatureAlgorithm]; *checkSigAlg && exists && certNum != len(chain)-1 {
				if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
					cErrs = append(cErrs, fmt.Errorf(errSunsetAlg, host.ServerName, cert.Subject.CommonName, alg.name))
				}
			}

			result.certs = append(result.certs, certErrors{
				commonName: cert.Subject.CommonName,
				errs:       cErrs,
			})
		}
	}

	return
}
