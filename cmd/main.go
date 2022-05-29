package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/sting8k/gowc/cmd/model"
	"github.com/sting8k/gowc/cmd/processor"
	"github.com/sting8k/gowc/cmd/utils"
	"github.com/sting8k/gowc/pkg/dnshandler"
)

type GoWcArgs struct {
	MassdnsCache string
	Domain       string
	Timeout      int
	Qps          int
	Output       string
	WithIp       bool
}

func craftOutput(gWC *model.GoWCModel) map[string][]string {

	output := make(map[string][]string)
	tmpRootDomains := gWC.GetRootDomains()
	ips := gWC.KnownWcResult
	var idx int
	var ok bool

	rootDomains := []string{}
	rootIps := []string{}

	for r := range tmpRootDomains {
		rootDomains = append(rootDomains, r)
	}

	for ip := range ips {
		rootIps = append(rootIps, ip)
	}

	for domain := range gWC.IpsCache {
		for _, rD := range rootDomains {
			if strings.Contains(domain, rD) && domain != rD {
				for _, rI := range rootIps {
					if ok, idx = utils.StringInSliceWithIndex(rI, gWC.IpsCache[domain]); ok {
						gWC.IpsCache[domain] = utils.RemoveIndex(gWC.IpsCache[domain], idx)
					}
				}
			}
		}
	}

	for d := range gWC.IpsCache {
		if len(gWC.IpsCache[d]) != 0 && !strings.HasPrefix(d, model.GeneratedMagicStr) {
			output[d] = gWC.IpsCache[d]
		}
	}
	return output
}

func saveToOutput(data map[string][]string, path string, withip bool) int {
	var output []string
	for d := range data {
		if withip {
			output = append(output, d+" ["+strings.Join(data[d], ", ")+"]")
		} else {
			output = append(output, d)
		}

	}
	sort.Strings(output)
	utils.WriteLines(output, path)
	return len(output)
}

func getNSOfTarget(domain string) ([]string, error) {
	var NSans []string
	options := &dnshandler.Options{
		BaseResolversNoPort: dnshandler.DefaultOptions.BaseResolversNoPort,
		BaseResolvers:       dnshandler.DefaultOptions.BaseResolvers,
		MaxRetries:          dnshandler.DefaultOptions.MaxRetries,
		Qps:                 1,
	}
	Resolvers := dnshandler.DefaultOptions.BaseResolvers

	dnsMachineNormal, err := dnshandler.InitDNSFactory(options)

	if err != nil {
		log.Fatal(err)
	}

	NSans = dnsMachineNormal.Query(domain, "NS")
	if len(NSans) != 0 {
		return NSans, nil
	}

	return Resolvers, errors.New("Empty NS")
}

// func processDomain(domain string, gWC *model.GoWCModel, dnsMachine *dnshandler.DNSFactory) bool {
// 	ips := gWC.Resolve(domain, dnsMachine)
// 	if len(ips) == 0 {
// 		return false
// 	}

// 	if gWC.IpIsWildcard(domain, ips[0]) {
// 		return true
// 	}

// 	parentDomain := model.GetParentDomain(domain)
// 	tmpDomain := model.GeneratedMagicStr + "." + parentDomain
// 	tmpDomainIps := gWC.Resolve(tmpDomain, dnsMachine)

// 	if utils.StringInSlice(ips[0], tmpDomainIps) {
// 		rootDomainCheck := gWC.GetRootOfWildcard(domain, dnsMachine)
// 		for _, IP := range tmpDomainIps {
// 			model.AddQueue(&gWC.KnownWcResult, IP, []string{rootDomainCheck}, model.KnownWcMutex)
// 		}
// 		return true
// 	}

// 	return false
// }

func CleanWildcards(domain string, gWC *model.GoWCModel) bool {
	ips := gWC.GetIpsFromCache(domain)
	if len(ips) == 0 {
		return false
	}

	if gWC.IpIsWildcard(domain, ips[0]) {
		return true
	}

	parentDomain := model.GetParentDomain(domain)
	tmpDomain := model.GeneratedMagicStr + "." + parentDomain
	tmpDomainIps := gWC.GetIpsFromCache(tmpDomain)

	if utils.StringInSlice(ips[0], tmpDomainIps) {
		rootDomainCheck := gWC.GetRootOfWildcardNewMethod(domain)
		for _, IP := range tmpDomainIps {
			model.AddQueue(&gWC.KnownWcResult, IP, []string{rootDomainCheck}, model.KnownWcMutex)
		}
		return true
	}

	return false
}

func ResolveNewDomains(domain string, gWC *model.GoWCModel, dnsMachine *dnshandler.DNSFactory) {
	gWC.PushToResolvePool(domain, dnsMachine)
	parentDomain := model.GetParentDomain(domain)
	tmpDomain := model.GeneratedMagicStr + "." + parentDomain
	gWC.PushToResolvePool(tmpDomain, dnsMachine)
	gWC.ResolveRootOfWildcard(domain, dnsMachine)
}

func Worker(gWC *model.GoWCModel, dnsMachine *dnshandler.DNSFactory, timeout int) {
	var domain string
	var err error
	for _, domain := range gWC.DomainsQueue {
		if domain != "" {
			ResolveNewDomains(domain, gWC, dnsMachine)
		}
	}

	go func() {
		dnsMachine.ActivateQueryPool("A")
		dnsMachine.ActivateQueryPool("CNAME")
		fmt.Printf("[+] Sending %d queries ...\n", dnsMachine.QueryCounter)
	}()

	ResolvedNewDomains := dnsMachine.ProcessQueryPool(timeout)

	for dm, ips := range ResolvedNewDomains {
		model.AddQueue(&gWC.IpsCache, dm, ips, model.IpsMutex)
	}

	fmt.Println("[i] Cleaning wildcards ...")
	for err == nil {
		domain, err = gWC.PopDomain()
		if domain != "" {
			CleanWildcards(domain, gWC)
		}
	}

}

// func worker(gWC *model.GoWCModel, dnsMachine *dnshandler.DNSFactory, wg *sync.WaitGroup) {
// 	var domain string
// 	var err error

// 	err = nil
// 	defer wg.Done()

// 	for err == nil {
// 		domain, err = gWC.PopDomain()
// 		if domain != "" {
// 			processDomain(domain, gWC, dnsMachine)
// 		}
// 	}
// }

// var wg sync.WaitGroup
// wg.Add(concurrency)
// for i := 0; i < concurrency; i++ {
// 	go worker(gWC, dnsMachineOrigin, &wg)
// }

// wg.Wait()

func argsParse() *GoWcArgs {
	banner := `
 ██████╗  ██████╗ ██╗    ██╗ ██████╗
██╔════╝ ██╔═══██╗██║    ██║██╔════╝
██║  ███╗██║   ██║██║ █╗ ██║██║     
██║   ██║██║   ██║██║███╗██║██║     
╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗
 ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝
                           GoWC v1.2					
`
	fmt.Print(banner)
	args := &GoWcArgs{}
	flag.StringVar(&args.MassdnsCache, "m", "", "Massdns output file")
	flag.StringVar(&args.Domain, "d", "", "Domain of target")
	flag.IntVar(&args.Timeout, "to", 10, "Timeout (Default: 10 seconds)")
	flag.IntVar(&args.Qps, "q", 10000, "Queries per second (Default: 10000 qps)")
	flag.StringVar(&args.Output, "o", "output.txt", "Output file")
	flag.BoolVar(&args.WithIp, "i", false, "Output with ips from massdns")
	flag.Parse()

	switch {
	case args.MassdnsCache == "":
		log.Fatal("Cannot open massdns cache file")
	case args.Domain == "":
		log.Fatal("We don't have any target")
	}

	return args
}

func main() {
	args := argsParse()
	// concurrency := args.Threads

	//Get root NS of target
	NSans, _ := getNSOfTarget(args.Domain)
	fmt.Printf("[+] Nameserver list: %q\n", append(NSans, dnshandler.DefaultOptions.BaseResolversNoPort...))
	//Initialize gWC model
	dnsMachineOrigin, _ := dnshandler.InitDNSFactory(&dnshandler.Options{
		BaseResolvers:       append(dnshandler.DefaultOptions.BaseResolvers, NSans...),
		BaseResolversNoPort: append(dnshandler.DefaultOptions.BaseResolversNoPort, NSans...),
		MaxRetries:          dnshandler.DefaultOptions.MaxRetries,
		Qps:                 args.Qps},
	)

	gWC := &model.GoWCModel{}
	gWC.Init()
	gWC.SetMainDomain(args.Domain)
	//Processing
	fmt.Println("[+] Processing MassDns cache file ...")
	processor.ProcessMassdnsCache(args.MassdnsCache, &gWC.DomainsQueue, &gWC.IpsCache)
	fmt.Printf("[+] %d subdomains to be checked\n", len(gWC.DomainsQueue))

	start := time.Now()
	Worker(gWC, dnsMachineOrigin, args.Timeout)

	elapsed := time.Since(start)
	output := craftOutput(gWC)
	fmt.Println("[i] Saving output to file: " + args.Output)
	validDomains := saveToOutput(output, args.Output, args.WithIp)
	fmt.Printf("[!] Found %d valid subdomains in %s\n", validDomains, elapsed)

}
