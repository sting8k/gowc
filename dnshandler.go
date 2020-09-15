package main

import (
	"errors"

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

func (d *DNSFactory) getNSRecords(domain string) []string {
	var results []string
	var tmp []string
	for _, resolver := range d.Resolvers {
		tmp, _ = getNSRecordWithCustomNS(domain, validateNSFmt(resolver))
		results = append(results, tmp...)
	}
	return RemoveDuplicates(results)
}

func (d *DNSFactory) getARecords(domain string) []string {
	var results []string
	var tmp []string
	for _, resolver := range d.Resolvers {
		tmp, _ = getARecordWithCustomNS(domain, validateNSFmt(resolver))
		results = append(results, tmp...)
	}
	return RemoveDuplicates(results)
}

func (d *DNSFactory) getCNAMERecords(domain string) []string {
	var results []string
	var tmp []string
	for _, resolver := range d.Resolvers {
		tmp, _ = getCNAMERecordWithCustomNS(domain, validateNSFmt(resolver))
		results = append(results, tmp...)
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

func getNSRecordWithCustomNS(domain string, resolver string) ([]string, error) {
	var result []string
	answer, err := makeQueryHeader(domain, resolver, miekgdns.TypeNS)
	if err != nil {
		return result, err
	}
	for _, record := range answer.Answer {
		if t, ok := record.(*miekgdns.NS); ok {
			result = append(result, NSparse(t.String()))
		}
	}
	return result, err
}

func getARecordWithCustomNS(domain string, resolver string) ([]string, error) {
	var result []string
	answer, err := makeQueryHeader(domain, resolver, miekgdns.TypeA)
	if err != nil {
		return result, err
	}
	for _, record := range answer.Answer {
		if t, ok := record.(*miekgdns.A); ok {
			result = append(result, t.A.String())
		}
	}
	return result, err
}

func getCNAMERecordWithCustomNS(domain string, resolver string) ([]string, error) {
	var result []string
	answer, err := makeQueryHeader(domain, resolver, miekgdns.TypeCNAME)
	if err != nil {
		return result, err
	}
	for _, record := range answer.Answer {
		if t, ok := record.(*miekgdns.CNAME); ok {
			result = append(result, CNAMEparse(t.String()))
		}
	}
	return result, err
}
