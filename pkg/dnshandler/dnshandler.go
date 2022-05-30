package dnshandler

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/caffix/resolve"
	miekgdns "github.com/miekg/dns"
	"github.com/sting8k/gowc/cmd/utils"
)

type DNSFactory struct {
	QueryCounter        int
	MaxRetries          int
	QueryPool           []string
	Resolvers           []string
	BaseResolversNoPort []string
	TypeMap             map[string]uint16
	QueryCount          map[string]int
	AnsChannel          chan *miekgdns.Msg
	ResolveEngine       *resolve.Resolvers
	ResolveEngineCtx    context.Context
	ResolveEngineCancel context.CancelFunc
}

type Options struct {
	Qps                 int
	MaxRetries          int
	BaseResolvers       []string
	BaseResolversNoPort []string
}

var DefaultOptions = Options{
	BaseResolvers:       []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"},
	BaseResolversNoPort: []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"},
	MaxRetries:          2,
	Qps:                 10000,
}

var QueryMutex = &sync.RWMutex{}

func InitDNSFactory(options *Options) (*DNSFactory, error) {
	theFactory := &DNSFactory{
		Resolvers:           options.BaseResolvers,
		BaseResolversNoPort: options.BaseResolversNoPort,
		TypeMap: map[string]uint16{
			"A":     miekgdns.TypeA,
			"NS":    miekgdns.TypeNS,
			"CNAME": miekgdns.TypeCNAME,
		},
		ResolveEngine: resolve.NewResolvers(),
		AnsChannel:    make(chan *miekgdns.Msg, options.Qps*2),
		QueryPool:     make([]string, 0),
		QueryCounter:  0,
		QueryCount:    make(map[string]int, 0),
	}
	// theFactory.Client.Timeout = 3 * 1e9
	theFactory.ResolveEngine.AddResolvers(options.Qps, theFactory.BaseResolversNoPort...)
	theFactory.ResolveEngineCtx, theFactory.ResolveEngineCancel = context.WithCancel(context.Background())
	return theFactory, nil
}

func (d *DNSFactory) PushQueryPool(domain string) {
	defer QueryMutex.Unlock()
	QueryMutex.Lock()
	if !utils.StringInSlice(domain, d.QueryPool) {
		d.QueryPool = append(d.QueryPool, domain)
	}

}

func (d *DNSFactory) ActivateQueryPool(queryType string) {
	for _, domain := range d.QueryPool {
		d.QueryCounter += 1
		strType := strconv.FormatUint(uint64(d.TypeMap[queryType]), 10)
		d.QueryCount[domain+strType] = 0
		d.ResolveEngine.Query(d.ResolveEngineCtx, resolve.QueryMsg(domain, d.TypeMap[queryType]), d.AnsChannel)
	}
}

func (d *DNSFactory) ProcessQueryPool(sectimeout int) map[string][]string {
	defer d.ResolveEngine.Stop()
	defer d.ResolveEngineCancel()
	lengthTimeout := time.Duration(sectimeout) * time.Second
	timedout := time.After(lengthTimeout)
	rs := make(map[string][]string, 0)
	// counter := 0

	for {
		select {
		case <-timedout:
			if len(d.AnsChannel) > 0 {
				timedout = time.After(lengthTimeout)
			} else {
				return rs
			}
		case resp := <-d.AnsChannel:
			// counter += 1
			// if counter%1000 == 0 {
			// 	fmt.Println("RESP:", counter, len(rs))
			// }
			timedout = time.After(lengthTimeout)
			if resp.Rcode == miekgdns.RcodeSuccess && len(resp.Answer) > 0 {
				for _, datum := range resolve.ExtractAnswers(resp) {
					if !utils.IntInSlice(datum.Type, []uint16{miekgdns.TypeA, miekgdns.TypeCNAME}) {
						continue
					}
					if _, ok := rs[datum.Name]; !ok {
						rs[datum.Name] = make([]string, 0)
						rs[datum.Name] = append(rs[datum.Name], datum.Data)
					} else {
						if !utils.StringInSlice(datum.Data, rs[datum.Name]) {
							rs[datum.Name] = append(rs[datum.Name], datum.Data)
						}
					}
				}
			} else if resp.Rcode == resolve.RcodeNoResponse {
				domain := resolve.RemoveLastDot(resp.Question[0].Name)
				strType := strconv.FormatUint(uint64(resp.Question[0].Qtype), 10)
				if d.QueryCount[domain+strType] <= d.MaxRetries {
					// fmt.Println("Retrying: ", domain, d.QueryCount[domain+strType], domain+strType)
					d.ResolveEngine.Query(d.ResolveEngineCtx, resolve.QueryMsg(domain, resp.Question[0].Qtype), d.AnsChannel)
					d.QueryCount[domain+strType]++
					continue
				}
			}

			d.QueryCounter--
		}
		if d.QueryCounter <= 0 {
			return rs
		}
	}
}

func (d *DNSFactory) queryPoolGetRecord(resp *miekgdns.Msg) []string {
	var result []string
	for _, record := range resp.Answer {
		if t, ok := record.(*miekgdns.NS); ok {
			result = append(result, utils.NSparse(t.String()))
		}
		if t, ok := record.(*miekgdns.A); ok {
			result = append(result, t.A.String())
		}
		if t, ok := record.(*miekgdns.CNAME); ok {
			result = append(result, utils.CNAMEparse(t.String()))
		}
	}
	return result
}

func (d *DNSFactory) Query(domain string, queryType string) []string {
	resultsPool := make([]string, 0)

	switch queryType {
	case "NS":
		for _, resolver := range d.Resolvers {
			tmp, _ := d.getRecordsWithCustomNS(domain, utils.ValidateNSFmt(resolver), "NS")
			resultsPool = append(resultsPool, tmp...)
		}
	case "A":
		for _, resolver := range d.Resolvers {
			tmp, err := d.getRecordsWithCustomNS(domain, utils.ValidateNSFmt(resolver), "A")
			resultsPool = append(resultsPool, tmp...)
			if err == nil {
				break
			}
		}

	case "CNAME":
		for _, resolver := range d.Resolvers {
			tmp, err := d.getRecordsWithCustomNS(domain, utils.ValidateNSFmt(resolver), "CNAME")
			resultsPool = append(resultsPool, tmp...)
			if err == nil {
				break
			}
		}

	}
	return utils.RemoveDuplicates(resultsPool)

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

	answer, err := d.makeQueryHeader(domain, resolver, d.TypeMap[queryType], d.MaxRetries)
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
