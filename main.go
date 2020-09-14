package main

import (
	"errors"
	"log"
	"strings"
	"sync"

	"github.com/miekg/dns"
	miekgdns "github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

// DNSFactory is structure to perform dns lookups
type DNSFactory struct {
	dnsClient *retryabledns.Client
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
	return &DNSFactory{dnsClient: dnsClient}, nil
}

func (d *DNSFactory) getNSRecords(domain string) ([]string, error) {
	var results []string
	tmpResults, _, err := d.dnsClient.ResolveRaw(domain, miekgdns.TypeNS)
	if err != nil {
		return nil, err
	}
	for _, value := range tmpResults {
		NSans := strings.Split(value, "NS")
		tmp := NSans[len(NSans)-1]
		tmp = strings.TrimSpace(strings.TrimSuffix(tmp, "."))
		results = append(results, tmp)
	}
	return results, nil
}

func (d *DNSFactory) getARecords(domain string) ([]string, error) {
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

func getARecordWithCustomNS(domain string, resolver string, AnswerPool chan []string, wg *sync.WaitGroup) ([]string, error) {
	var result []string
	msg := new(miekgdns.Msg)
	defer wg.Done()

	msg.Id = miekgdns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]miekgdns.Question, 1)
	msg.Question[0] = miekgdns.Question{
		Name:   miekgdns.Fqdn(domain),
		Qtype:  miekgdns.TypeA,
		Qclass: miekgdns.ClassINET,
	}

	var err error
	var answer *miekgdns.Msg

	answer, err = dns.Exchange(msg, resolver)
	if err != nil {
		AnswerPool <- result
		return result, err
	}

	// In case we got some error from the server, return.
	if answer != nil && answer.Rcode != miekgdns.RcodeSuccess {
		AnswerPool <- result
		return result, errors.New(miekgdns.RcodeToString[answer.Rcode])
	}

	for _, record := range answer.Answer {
		if t, ok := record.(*miekgdns.A); ok {
			result = append(result, t.A.String())
		}
	}

	AnswerPool <- result
	return result, err
}

func main() {

	var NSans []string

	var wg sync.WaitGroup

	options := &Options{
		BaseResolvers: DefaultOptions.BaseResolvers,
		MaxRetries:    DefaultOptions.MaxRetries,
	}
	hostname := "spotify.com"

	dnsMachine, err := InitDNSFactory(options)

	if err != nil {
		log.Fatal(err)
	}

	NSans, err = dnsMachine.getNSRecords(hostname)

	if err != nil {
		log.Fatal(err)
	}

	AnswerPool := make(chan []string, len(NSans))
	for _, value := range NSans {
		wg.Add(1)
		log.Println(value)
		go getARecordWithCustomNS("test151562262245.spotify.com", value+":53", AnswerPool, &wg)
	}

	wg.Wait()
	close(AnswerPool)

	for rs := range AnswerPool {
		log.Println(rs)
	}

	log.Println("Exited")

}
