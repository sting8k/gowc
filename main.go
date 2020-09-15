package main

import (
	"log"
	"strconv"
	"sync"
)

func printResult(gWC *goWCModel) {
	domains := gWC.getRootDomains()
	log.Println(domains)
	for _, value := range domains {
		log.Println(value)
	}
	log.Println("Resolve Queries: " + strconv.Itoa(counter))

}

func saveRootWildcardDomains(gWC *goWCModel, path string) {
	domains := gWC.getRootDomains()
	var output []string
	for d := range domains {
		output = append(output, d)
	}
	writeLines(output, path)
}

func saveIpsWildcard(gWC *goWCModel, path string) {
	ips := gWC.knownWcResult
	var output []string
	for ip := range ips {
		output = append(output, ip)
	}
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
	}

	NSans = DefaultOptions.BaseResolvers
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
		//log.Println("WC: " + domain)
		rootDomainCheck := gWC.getRootOfWildcard(domain, dnsMachine)
		//log.Println("WCRoot: " + rootDomainCheck)
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

func main() {

	concurrency := 20
	//Get root NS of target
	NSans := getNSOfTarget("viettel.vn")

	//Initialize gWC model
	dnsMachineOrigin, _ := InitDNSFactory(&Options{BaseResolvers: NSans})
	gWC := &goWCModel{}
	gWC.init()

	//Processing
	//processMassdnsCache("/tmp/ohdns.2bHLRD5j/massdns.txt", &gWC.domainsQueue, &gWC.ipsCache)
	//processMassdnsCache("/tmp/ohdns.W5uy9chX/massdns.txt", &gWC.domainsQueue, &gWC.ipsCache)
	//processMassdnsCache("/tmp/ohdns.fVBykYYS/massdns.txt", &gWC.domainsQueue, &gWC.ipsCache)
	processMassdnsCache("/tmp/ohdns.lp791jHZ/massdns_tmp1.txt", &gWC.domainsQueue, &gWC.ipsCache) // viettel
	//processMassdnsCache("/tmp/ohdns.AjvenFjk/massdns_tmp1.txt", &gWC.domainsQueue, &gWC.ipsCache) // vk.com

	log.Println("Process Massdns cache...")
	log.Println(len(gWC.domainsQueue))

	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go worker(gWC, dnsMachineOrigin, &wg)
	}

	wg.Wait()
	log.Println("All goroutines done!")
	//printResult(gWC)
	//log.Println(gWC.ipsCache)
	var test []string
	for d := range gWC.ipsCache {
		test = append(test, d)
	}
	writeLines(test, "/tmp/goIPscache.txt")
	saveRootWildcardDomains(gWC, "/tmp/gowcrootwc.txt")
	saveIpsWildcard(gWC, "/tmp/gowcIps.txt")

	log.Println("Exited")

}
