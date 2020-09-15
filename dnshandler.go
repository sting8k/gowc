package main

import (
	"errors"
	"sync"

	miekgdns "github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

type DNSFactory struct {
	dnsClient *retryabledns.Client
	Resolvers []string
}

type Options struct {
	BaseResolvers []string
	MaxRetries    int
}

var DefaultOptions = Options{
	BaseResolvers: []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"},
	MaxRetries:    3,
}

func InitDNSFactory(options *Options) (*DNSFactory, error) {
	dnsClient := retryabledns.New(options.BaseResolvers, options.MaxRetries)
	return &DNSFactory{dnsClient: dnsClient, Resolvers: options.BaseResolvers}, nil
}

func (d *DNSFactory) fastNSRecords(domain string) ([]string, error) {
	var results []string
	tmpResults, _, err := d.dnsClient.ResolveRaw(domain, miekgdns.TypeNS)
	if err != nil {
		return nil, err
	}
	for _, value := range tmpResults {
		NSans := NSparse(value)
		results = append(results, NSans)
	}
	return results, nil
}

func (d *DNSFactory) fastARecords(domain string) ([]string, error) {
	var results []string
	tmpResults, err := d.dnsClient.Resolve(domain)
	if err != nil {
		return nil, err
	}
	for _, value := range tmpResults.IPs {
		results = append(results, value)
	}
	return results, nil
}

func (d *DNSFactory) fastCNAMERecords(domain string) ([]string, error) {
	var results []string
	tmpResults, _, err := d.dnsClient.ResolveRaw(domain, miekgdns.TypeCNAME)

	if err != nil {
		return nil, err
	}
	for _, value := range tmpResults {
		Cans := CNAMEparse(value)
		results = append(results, Cans)
	}
	return results, nil
}

func (d *DNSFactory) query(domain string, queryType string) []string {
	var results []string
	resultsChannel := make(chan []string, len(d.Resolvers))
	var wg sync.WaitGroup
	wg.Add(len(d.Resolvers))

	switch queryType {
	case "NS":
		for _, resolver := range d.Resolvers {
			go func(domain, resolver string) {
				defer wg.Done()
				var tmp []string
				tmp, _ = getRecordsWithCustomNS(domain, validateNSFmt(resolver), "NS")
				resultsChannel <- tmp
			}(domain, resolver)
		}
	case "A":
		for _, resolver := range d.Resolvers {
			go func(domain, resolver string) {
				defer wg.Done()
				var tmp []string
				tmp, _ = getRecordsWithCustomNS(domain, validateNSFmt(resolver), "A")
				resultsChannel <- tmp
			}(domain, resolver)
		}

	case "CNAME":
		for _, resolver := range d.Resolvers {
			go func(domain, resolver string) {
				defer wg.Done()
				var tmp []string
				tmp, _ = getRecordsWithCustomNS(domain, validateNSFmt(resolver), "CNAME")
				resultsChannel <- tmp
			}(domain, resolver)
		}

	}
	wg.Wait()
	close(resultsChannel)
	for r := range resultsChannel {
		results = append(results, r...)
	}
	return RemoveDuplicates(results)

}

func makeQueryHeader(domain, resolver string, queryType uint16) (*miekgdns.Msg, error) {
	msg := new(miekgdns.Msg)

	msg.Id = miekgdns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]miekgdns.Question, 1)
	msg.Question[0] = miekgdns.Question{
		Name:   miekgdns.Fqdn(domain),
		Qtype:  queryType,
		Qclass: miekgdns.ClassINET,
	}

	var err error
	var answer *miekgdns.Msg

	answer, err = miekgdns.Exchange(msg, resolver)
	if err != nil {
		return nil, err
	}

	// In case we got some error from the server, return.
	if answer != nil && answer.Rcode != miekgdns.RcodeSuccess {
		return nil, errors.New(miekgdns.RcodeToString[answer.Rcode])
	}
	return answer, err
}

func getRecordsWithCustomNS(domain, resolver, queryType string) ([]string, error) {
	var result []string
	typeMap := map[string]uint16{
		"A":     miekgdns.TypeA,
		"NS":    miekgdns.TypeNS,
		"CNAME": miekgdns.TypeCNAME,
	}

	answer, err := makeQueryHeader(domain, resolver, typeMap[queryType])
	if err != nil {
		return result, err
	}
	for _, record := range answer.Answer {
		switch queryType {
		case "NS":
			if t, ok := record.(*miekgdns.NS); ok {
				result = append(result, NSparse(t.String()))
			}
		case "A":
			if t, ok := record.(*miekgdns.A); ok {
				result = append(result, t.A.String())
			}
		case "CNAME":
			if t, ok := record.(*miekgdns.CNAME); ok {
				result = append(result, CNAMEparse(t.String()))
			}
		}
	}

	return result, err
}
