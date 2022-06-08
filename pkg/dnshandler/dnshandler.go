package dnshandler

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
	miekgdns "github.com/miekg/dns"
	"github.com/sting8k/gowc/cmd/utils"
)

type DNSFactory struct {
	QueryCounter        int
	MaxRetries          int
	QueryDict           map[string]struct{}
	QueryPool           chan string
	BaseResolvers       []string
	TypeMap             map[string]uint16
	QueryCount          map[string]int
	AnsChannel          chan *miekgdns.Msg
	SubChannel          chan []string
	ResolveEngine       *resolve.Resolvers
	ResolveEngineCtx    context.Context
	ResolveEngineCancel context.CancelFunc
}

type Options struct {
	Qps           int
	MaxRetries    int
	BaseResolvers []string
}

var DefaultOptions = Options{
	BaseResolvers: []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"},
	MaxRetries:    2,
	Qps:           10000,
}

var QueryMutex = &sync.RWMutex{}

func InitDNSFactory(options *Options) (*DNSFactory, error) {
	theFactory := &DNSFactory{
		BaseResolvers: options.BaseResolvers,
		TypeMap: map[string]uint16{
			"A":     miekgdns.TypeA,
			"NS":    miekgdns.TypeNS,
			"CNAME": miekgdns.TypeCNAME,
		},
		ResolveEngine: resolve.NewResolvers(),
		AnsChannel:    make(chan *miekgdns.Msg, options.Qps*3),
		SubChannel:    make(chan []string, options.Qps),
		QueryDict:     make(map[string]struct{}, 0),
		QueryPool:     make(chan string, options.Qps),
		QueryCounter:  0,
		QueryCount:    make(map[string]int, 0),
	}
	theFactory.ResolveEngine.AddResolvers(options.Qps, theFactory.BaseResolvers...)
	theFactory.ResolveEngineCtx, theFactory.ResolveEngineCancel = context.WithCancel(context.Background())

	return theFactory, nil
}

func (d *DNSFactory) PrepareQueryPool() {
	go func() {
		for domain := range d.QueryDict {
			d.QueryPool <- domain
		}
		// d.QueryDict = nil
	}()
}

func (d *DNSFactory) _ActivateQueryWithQType(domain, queryType string) {
	d.QueryCounter += 1
	strType := strconv.FormatUint(uint64(d.TypeMap[queryType]), 10)
	d.QueryCount[domain+strType] = 0
	d.ResolveEngine.Query(d.ResolveEngineCtx, resolve.QueryMsg(domain, d.TypeMap[queryType]), d.AnsChannel)
}

func (d *DNSFactory) RetryQuery(loadedresp *miekgdns.Msg) {
	domain := strings.ToLower(resolve.RemoveLastDot(loadedresp.Question[0].Name))
	strType := strconv.FormatUint(uint64(loadedresp.Question[0].Qtype), 10)
	if d.QueryCount[domain+strType] <= d.MaxRetries {
		d.QueryCount[domain+strType]++
		// go func(rx *miekgdns.Msg) {
		rx := loadedresp
		// ans := make([]string, 0)
		dm := strings.ToLower(resolve.RemoveLastDot(rx.Question[0].Name))
		switch rx.Question[0].Qtype {
		case dns.TypeA:
			d.QueryCounter++
			go func(dm string) {
				dX := append([]string{dm}, d.GreedyQuery(dm, "A")...)
				d.SubChannel <- dX
			}(dm)

		case dns.TypeCNAME:
			d.QueryCounter++
			go func(dm string) {
				dX := append([]string{dm}, d.GreedyQuery(dm, "CNAME")...)
				d.SubChannel <- dX
			}(dm)
		}
	}
}

func (d *DNSFactory) ProcessPool(sectimeout int) map[string][]string {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	// defer close(d.QueryPool)
	// defer close(d.AnsChannel)
	lengthTimeout := time.Duration(sectimeout) * time.Second
	timedout := time.After(lengthTimeout)
	rs := make(map[string][]string, 0)
	// counter := 0

	for {
		select {
		case <-t.C:
			if d.QueryCounter <= 0 {
				return rs
			}
		case <-timedout:
			if len(d.AnsChannel) > 0 {
				timedout = time.After(lengthTimeout)
			} else {
				d.QueryCounter = 0
				return rs
			}
		case domainX := <-d.QueryPool:
			timedout = time.After(lengthTimeout)
			d._ActivateQueryWithQType(domainX, "A")
			d._ActivateQueryWithQType(domainX, "CNAME")
		case ans := <-d.SubChannel:
			timedout = time.After(lengthTimeout)
			if len(ans) > 1 {
				dm := ans[0]
				QueryMutex.Lock()
				if _, ok := rs[dm]; !ok {
					rs[dm] = make([]string, 0)
					rs[dm] = append(rs[dm], ans[1:]...)
				} else {
					rs[dm] = append(rs[dm], ans[1:]...)
					rs[dm] = utils.RemoveDuplicates(rs[dm])
				}
				QueryMutex.Unlock()
			}
			d.QueryCounter--
		case resp := <-d.AnsChannel:
			timedout = time.After(lengthTimeout)
			// domain := strings.ToLower(resolve.RemoveLastDot(resp.Question[0].Name))
			// strType := strconv.FormatUint(uint64(resp.Question[0].Qtype), 10)
			if resp.Rcode == miekgdns.RcodeSuccess {
				if len(resp.Answer) > 0 {
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
				} else {
					d.RetryQuery(resp)
					continue
				}

			} else if resp.Rcode == resolve.RcodeNoResponse {
				// domain := strings.ToLower(resolve.RemoveLastDot(resp.Question[0].Name))
				// strType := strconv.FormatUint(uint64(resp.Question[0].Qtype), 10)
				// if d.QueryCount[domain+strType] <= d.MaxRetries {
				// 	d.ResolveEngine.Query(d.ResolveEngineCtx, resolve.QueryMsg(domain, resp.Question[0].Qtype), d.AnsChannel)
				// 	d.QueryCount[domain+strType]++
				// 	continue
				// }
				d.RetryQuery(resp)
				continue
			}

			d.QueryCounter--

		}

		// if d.QueryCounter%1 == 0 {
		fmt.Printf("\rQueryRemaining %d", d.QueryCounter)
		// fmt.Println(d.QueryCounter)
		// }

		if d.QueryCounter <= 0 {
			return rs
		}
	}
}

func (d *DNSFactory) StopPool() {
	defer d.ResolveEngine.Stop()
	defer d.ResolveEngineCancel()
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

func (d *DNSFactory) GreedyQuery(domain string, queryType string) []string {
	resultsPool := make([]string, 0)

	switch queryType {
	case "NS":
		for _, resolver := range d.BaseResolvers {
			tmp, _ := d.getRecordsWithCustomNS(domain, utils.ValidateNSFmt(resolver), "NS")
			resultsPool = append(resultsPool, tmp...)
		}
	case "A":
		for _, resolver := range d.BaseResolvers {
			tmp, err := d.getRecordsWithCustomNS(domain, utils.ValidateNSFmt(resolver), "A")
			resultsPool = append(resultsPool, tmp...)
			if err == nil {
				break
			}
		}

	case "CNAME":
		for _, resolver := range d.BaseResolvers {
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
