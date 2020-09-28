package main

import (
	"flag"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/sting8k/gowc/dnshandler"
	"github.com/sting8k/gowc/utils"
)

type GoWcArgs struct {
	MassdnsCache string
	Domain       string
	Threads      int
	Output       string
	WithIp       bool
}

func craftOutput(gWC *goWCModel) map[string][]string {

	output := make(map[string][]string)
	tmpRootDomains := gWC.getRootDomains()
	ips := gWC.knownWcResult
	var flag int
	var ok bool

	rootDomains := []string{}
	rootIps := []string{}

	for r := range tmpRootDomains {
		rootDomains = append(rootDomains, r)
	}

	for ip := range ips {
		rootIps = append(rootIps, ip)
	}

	for domain := range gWC.ipsCache {
		for _, rD := range rootDomains {
			if strings.Contains(domain, rD) && domain != rD {
				for _, rI := range rootIps {
					ok, flag = utils.StringInSliceWithIndex(rI, gWC.ipsCache[domain])
					if ok {
						gWC.ipsCache[domain] = utils.RemoveIndex(gWC.ipsCache[domain], flag)
					}
				}
			}
		}
	}

	for d := range gWC.ipsCache {
		if len(gWC.ipsCache[d]) != 0 {
			output[d] = gWC.ipsCache[d]
		}
	}
	return output
}

func saveToOutput(data map[string][]string, path string, withip bool) {
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
}

func getNSOfTarget(domain string) []string {
	var NSans []string
	options := &dnshandler.Options{
		BaseResolvers: dnshandler.DefaultOptions.BaseResolvers,
		MaxRetries:    dnshandler.DefaultOptions.MaxRetries,
	}
	Resolvers := dnshandler.DefaultOptions.BaseResolvers

	dnsMachineNormal, err := dnshandler.InitDNSFactory(options)

	if err != nil {
		log.Fatal(err)
	}

	NSans = dnsMachineNormal.Query(domain, "NS")
	if len(NSans) != 0 {
		Resolvers = append(Resolvers, NSans...)
	}

	return Resolvers
}

func processDomain(domain string, gWC *goWCModel, dnsMachine *dnshandler.DNSFactory) bool {
	ips := gWC.resolve(domain, dnsMachine)
	if len(ips) == 0 {
		return false
	}

	if gWC.ipIsWildcard(domain, ips[0]) {
		return true
	}

	parentDomain := GetParentDomain(domain)
	tmpDomain := GeneratedMagicStr + "." + parentDomain
	tmpDomainIps := gWC.resolve(tmpDomain, dnsMachine)

	if utils.StringInSlice(ips[0], tmpDomainIps) {
		rootDomainCheck := gWC.getRootOfWildcard(domain, dnsMachine)
		for _, IP := range tmpDomainIps {
			AddQueue(&gWC.knownWcResult, IP, []string{rootDomainCheck}, knownWcMutex)
		}
		return true
	}

	return false
}

func worker(gWC *goWCModel, dnsMachine *dnshandler.DNSFactory, wg *sync.WaitGroup) {
	var domain string
	var err error

	err = nil
	defer wg.Done()

	for err == nil {
		domain, err = gWC.popDomain()
		if domain != "" {
			processDomain(domain, gWC, dnsMachine)
		}
	}
}

func argsParse() *GoWcArgs {
	banner := `
 ██████╗  ██████╗ ██╗    ██╗ ██████╗
██╔════╝ ██╔═══██╗██║    ██║██╔════╝
██║  ███╗██║   ██║██║ █╗ ██║██║     
██║   ██║██║   ██║██║███╗██║██║     
╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗
 ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝
                           GoWC v1.0					
`
	fmt.Print(banner)
	args := &GoWcArgs{}
	flag.StringVar(&args.MassdnsCache, "m", "", "Massdns output file")
	flag.StringVar(&args.Domain, "d", "", "Domain of target")
	flag.IntVar(&args.Threads, "t", 10, "Threads")
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

	// cpuprofile := "gowc.prof"
	// f, err := os.Create(cpuprofile)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// pprof.StartCPUProfile(f)
	// defer pprof.StopCPUProfile()

	concurrency := args.Threads

	//Get root NS of target
	NSans := getNSOfTarget(args.Domain)
	fmt.Printf("Nameserver list: %q\n", NSans)

	//Initialize gWC model
	dnsMachineOrigin, _ := dnshandler.InitDNSFactory(&dnshandler.Options{BaseResolvers: NSans, MaxRetries: dnshandler.DefaultOptions.MaxRetries})
	gWC := &goWCModel{}
	gWC.init()

	//Processing
	fmt.Println("Processing MassDns cache file ...")
	utils.ProcessMassdnsCache(args.MassdnsCache, &gWC.domainsQueue, &gWC.ipsCache)
	fmt.Printf("%d subdomains to be checked!\n", len(gWC.domainsQueue))
	fmt.Println("Invoke threads to clean Wildcards ...")
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go worker(gWC, dnsMachineOrigin, &wg)
	}

	wg.Wait()
	fmt.Println("All threads done!")
	output := craftOutput(gWC)
	fmt.Println("Saving output to file: " + args.Output)
	saveToOutput(output, args.Output, args.WithIp)
	fmt.Println("Done!")

}
