package main

import (
	"log"
	"sync"
)

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
		log.Println("WC: " + domain)
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
	log.Println(err)
}

func printResult(gWC *goWCModel) {
	domains := gWC.getRootDomains()
	log.Println(domains)
	for _, value := range domains {
		log.Println(value)
	}

}

func main() {

	concurrency := 1
	var NSans []string
	options := &Options{
		BaseResolvers: DefaultOptions.BaseResolvers,
		MaxRetries:    DefaultOptions.MaxRetries,
	}
	dnsMachineNormal, err := InitDNSFactory(options)

	if err != nil {
		log.Fatal(err)
	}

	hostname := "netflix.com"
	NSans = dnsMachineNormal.getNSRecords(hostname)

	dnsMachineOrigin, _ := InitDNSFactory(&Options{BaseResolvers: NSans})

	gWC := &goWCModel{}
	gWC.init()

	processMassdnsCache("/tmp/ohdns.2bHLRD5j/massdns.txt", &gWC.domainsQueue, &gWC.ipsCache)
	//processMassdnsCache("/tmp/ohdns.W5uy9chX/massdns.txt", &gWC.domainsQueue, &gWC.ipsCache)
	//processMassdnsCache("/tmp/ohdns.fVBykYYS/massdns.txt", &gWC.domainsQueue, &gWC.ipsCache)

	log.Println("Process Massdns cache...")

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		worker(gWC, dnsMachineOrigin, &wg)
	}

	wg.Wait()
	printResult(gWC)
	log.Println("Exited")

}
