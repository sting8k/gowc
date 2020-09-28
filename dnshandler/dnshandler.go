package dnshandler

import (
	"errors"

	"github.com/sting8k/gowc/utils"

	miekgdns "github.com/miekg/dns"
)

type DNSFactory struct {
	Resolvers  []string
	MaxRetries int
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
	return &DNSFactory{Resolvers: options.BaseResolvers, MaxRetries: options.MaxRetries}, nil
}

func (d *DNSFactory) Query(domain string, queryType string) []string {

	var results []string
	var tmp []string
	var err error
	tmpResolvers := d.Resolvers
	resultsChannel := make(chan []string, len(tmpResolvers))

	switch queryType {
	case "NS":
		for _, resolver := range tmpResolvers {
			tmp, err = d.getRecordsWithCustomNS(domain, utils.ValidateNSFmt(resolver), "NS")
			resultsChannel <- tmp
		}
	case "A":
		for _, resolver := range tmpResolvers {
			tmp, err = d.getRecordsWithCustomNS(domain, utils.ValidateNSFmt(resolver), "A")
			resultsChannel <- tmp
			if err == nil {
				break
			}
		}

	case "CNAME":
		for _, resolver := range tmpResolvers {
			tmp, err = d.getRecordsWithCustomNS(domain, utils.ValidateNSFmt(resolver), "CNAME")
			resultsChannel <- tmp
			if err == nil {
				break
			}
		}

	}
	close(resultsChannel)
	for r := range resultsChannel {
		results = append(results, r...)
	}
	return utils.RemoveDuplicates(results)

}

func (d *DNSFactory) makeQueryHeader(domain, resolver string, queryType uint16, retries int) (*miekgdns.Msg, error) {
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

	for i := 0; i <= retries; i++ {
		answer, err = miekgdns.Exchange(msg, resolver)
		if err != nil {
			continue
		}

		// In case we got some error from the server, return.
		if answer != nil && answer.Rcode != miekgdns.RcodeSuccess {
			return nil, errors.New(miekgdns.RcodeToString[answer.Rcode])
		}
		return answer, err
	}

	return answer, err
}

func (d *DNSFactory) getRecordsWithCustomNS(domain, resolver, queryType string) ([]string, error) {
	var result []string
	typeMap := map[string]uint16{
		"A":     miekgdns.TypeA,
		"NS":    miekgdns.TypeNS,
		"CNAME": miekgdns.TypeCNAME,
	}

	answer, err := d.makeQueryHeader(domain, resolver, typeMap[queryType], d.MaxRetries)
	if err != nil {
		return result, err
	}
	for _, record := range answer.Answer {
		switch queryType {
		case "NS":
			if t, ok := record.(*miekgdns.NS); ok {
				result = append(result, utils.NSparse(t.String()))
			}
		case "A":
			if t, ok := record.(*miekgdns.A); ok {
				result = append(result, t.A.String())
			}
		case "CNAME":
			if t, ok := record.(*miekgdns.CNAME); ok {
				result = append(result, utils.CNAMEparse(t.String()))
			}
		}
	}
	return result, err
}
