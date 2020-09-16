package main

import (
	"flag"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
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
					ok, flag = stringInSliceWithIndex(rI, gWC.ipsCache[domain])
					if ok {
						gWC.ipsCache[domain] = RemoveIndex(gWC.ipsCache[domain], flag)
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
	writeLines(output, path)
}

func getNSOfTarget(domain string) []string {
	var NSans []string
	options := &Options{
		BaseResolvers: DefaultOptions.BaseResolvers,
		MaxRetries:    DefaultOptions.MaxRetries,
	}
	dnsMachineNormal, err := InitDNSFactory(options)

	if err != nil {
		log.Fatal(err)
	}

	NSans = dnsMachineNormal.query(domain, "NS")
	if len(NSans) == 0 {
		log.Println("Cannot get any origin NS")
		NSans = DefaultOptions.BaseResolvers
	}

	return NSans
}

func processDomain(domain string, gWC *goWCModel, dnsMachine *DNSFactory) bool {
	ips := gWC.resolve(domain, dnsMachine)
	if len(ips) == 0 {
		return false
	}

	if gWC.ipIsWildcard(domain, ips[0]) {
		return true
	}

	parentDomain := getParentDomain(domain)
	tmpDomain := GeneratedMagicStr + "." + parentDomain
	tmpDomainIps := gWC.resolve(tmpDomain, dnsMachine)

	if stringInSlice(ips[0], tmpDomainIps) {
		rootDomainCheck := gWC.getRootOfWildcard(domain, dnsMachine)
		for _, IP := range tmpDomainIps {
			addQueue(&gWC.knownWcResult, IP, []string{rootDomainCheck}, knownWcMutex)
		}
		return true
	}

	return false
}

func worker(gWC *goWCModel, dnsMachine *DNSFactory, wg *sync.WaitGroup) {
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
	args := &GoWcArgs{}
	flag.StringVar(&args.MassdnsCache, "m", "", "Massdns output file")
	flag.StringVar(&args.Domain, "d", "", "Massdns output file")
	flag.IntVar(&args.Threads, "t", 20, "Threads")
	flag.StringVar(&args.Output, "o", "output.txt", "Output file")
	flag.BoolVar(&args.WithIp, "i", false, "Output with ips from massdns")
	flag.Parse()

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
	concurrency := args.Threads

	//Get root NS of target
	NSans := getNSOfTarget(args.Domain)

	//Initialize gWC model
	dnsMachineOrigin, _ := InitDNSFactory(&Options{BaseResolvers: NSans})
	gWC := &goWCModel{}
	gWC.init()

	//Processing
	fmt.Println("Processing MassDns cache file ...")
	processMassdnsCache(args.MassdnsCache, &gWC.domainsQueue, &gWC.ipsCache)

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
