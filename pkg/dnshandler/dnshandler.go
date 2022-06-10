package dnshandler

import (
	"context"
	"errors"
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
	KillSwitch          chan bool
	QueryCounter        int
	MaxRetries          int
	QueryDict           map[string]struct{}
	QueryPool           chan string
	BaseResolvers       []string
	TypeMap             map[string]uint16
	RetryCounter        map[string]int
	AnsMap              chan []string
	AnsChannel          chan *miekgdns.Msg
	SubChannel          chan []string
	ResolveEngine       *resolve.Resolvers
	ResolveEngineCtx    context.Context
	ResolveEngineCancel context.CancelFunc
}

type Options struct {
	Qps           int
	MaxRetries    int
	Timeout       int
	BaseResolvers []string
}

var DefaultOptions = Options{
	BaseResolvers: []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"},
	MaxRetries:    2,
	Qps:           10000,
	Timeout:       5,
}

var QueryMutex = &sync.RWMutex{}

func InitDNSFactory(options *Options) (*DNSFactory, error) {
	theFactory := &DNSFactory{
		KillSwitch:    make(chan bool, 1),
		BaseResolvers: options.BaseResolvers,
		TypeMap: map[string]uint16{
			"A":     miekgdns.TypeA,
			"NS":    miekgdns.TypeNS,
			"CNAME": miekgdns.TypeCNAME,
		},
		ResolveEngine: resolve.NewResolvers(),
		AnsMap:        make(chan []string, options.Qps*3),
		AnsChannel:    make(chan *miekgdns.Msg, options.Qps*3),
		SubChannel:    make(chan []string, options.Qps),
		QueryDict:     make(map[string]struct{}, 0),
		QueryPool:     make(chan string, options.Qps),
		QueryCounter:  0,
		RetryCounter:  make(map[string]int, 0),
	}
	theFactory.ResolveEngine.AddResolvers(options.Qps, theFactory.BaseResolvers...)
	theFactory.ResolveEngine.SetTimeout(time.Duration(options.Timeout) * time.Second)
	theFactory.ResolveEngineCtx, theFactory.ResolveEngineCancel = context.WithCancel(context.Background())

	return theFactory, nil
}

func (d *DNSFactory) PrepareQueryPool() {
	go func() {
		for domain := range d.QueryDict {
			d.QueryPool <- domain
		}
	}()
}

func (d *DNSFactory) _ActivateQueryWithQType(domain, queryType string) {
	d.QueryCounter += 1
	strType := strconv.FormatUint(uint64(d.TypeMap[queryType]), 10)
	d.RetryCounter[domain+strType] = 0
	d.ResolveEngine.Query(d.ResolveEngineCtx, resolve.QueryMsg(domain, d.TypeMap[queryType]), d.AnsChannel)
}

func (d *DNSFactory) RetryQuery(loadedresp *miekgdns.Msg) {
	domain := strings.ToLower(resolve.RemoveLastDot(loadedresp.Question[0].Name))
	strType := strconv.FormatUint(uint64(loadedresp.Question[0].Qtype), 10)

	if d.RetryCounter[domain+strType] <= d.MaxRetries {
		d.RetryCounter[domain+strType]++
		// go func(rx *miekgdns.Msg) {
		switch loadedresp.Question[0].Qtype {
		case dns.TypeA:
			d.QueryCounter++
			go func(dm string) {
				dX := append([]string{dm}, d.GreedyQuery(dm, "A")...)
				d.SubChannel <- dX
			}(domain)

		case dns.TypeCNAME:
			d.QueryCounter++
			go func(dm string) {
				dX := append([]string{dm}, d.GreedyQuery(dm, "CNAME")...)
				d.SubChannel <- dX
			}(domain)
		}
	} else {
		d.SubChannel <- []string{domain}
	}
}

func (d *DNSFactory) ProcessPool(sectimeout int) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	lengthTimeout := time.Duration(sectimeout) * time.Second
	timedout := time.After(lengthTimeout)

	for {
		select {
		case <-timedout: // do nothing
			if len(d.AnsChannel) > 0 {
				timedout = time.After(lengthTimeout)
			}
		case <-d.KillSwitch:
			close(d.KillSwitch)
			return
		case domainX := <-d.QueryPool:
			timedout = time.After(lengthTimeout)

			d._ActivateQueryWithQType(domainX, "A")
			d._ActivateQueryWithQType(domainX, "CNAME")
		case ans := <-d.SubChannel:
			timedout = time.After(lengthTimeout)
			if len(ans) >= 1 {
				d.AnsMap <- ans
			}
			//noted  d.QueryCounter--
		case resp := <-d.AnsChannel:
			timedout = time.After(lengthTimeout)
			domain := strings.ToLower(resolve.RemoveLastDot(resp.Question[0].Name))
			strType := strconv.FormatUint(uint64(resp.Question[0].Qtype), 10)
			if resp.Rcode == miekgdns.RcodeSuccess || resp.Rcode == miekgdns.RcodeNameError {
				if len(resp.Answer) > 0 {
					for _, datum := range resolve.ExtractAnswers(resp) {
						if !utils.IntInSlice(datum.Type, []uint16{miekgdns.TypeA, miekgdns.TypeCNAME}) {
							continue
						}
						d.AnsMap <- []string{domain, datum.Data}
					}
				} else if resp.Rcode == miekgdns.RcodeNameError {
					d.AnsMap <- []string{domain}
				} else {
					d.RetryQuery(resp)
					continue
				}

			} else {
				if d.RetryCounter[domain+strType] <= d.MaxRetries {
					d.ResolveEngine.Query(d.ResolveEngineCtx, resolve.QueryMsg(domain, resp.Question[0].Qtype), d.AnsChannel)
					d.RetryCounter[domain+strType]++
					continue
				} else {
					d.SubChannel <- []string{domain}
				}

			}
		default:
			continue
			//noted d.QueryCounter--

		}

		// if d.QueryCounter%1 == 0 {
		// 	fmt.Printf("\rQueryRemaining %d", d.QueryCounter)
		// }

		// if d.QueryCounter <= 0 {
		// 	return
		// }
	}
}

func (d *DNSFactory) StopResolveEngine() {
	defer d.ResolveEngineCancel()
	defer d.ResolveEngine.Stop()
	defer close(d.QueryPool)
	d.QueryCounter = -1
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
