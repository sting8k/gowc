package main

import (
	"log"
	"sync"
)

func dnsWoker(domain string, resolver string, AnswerPool chan []string, wg *sync.WaitGroup) {
	defer wg.Done()
	result, _ := getARecordWithCustomNS(domain, resolver)
	AnswerPool <- result
}

func test() {
	gWC := &goWCModel{
		ipsCache: make(map[string][]string),
	}
	a := []string{"acdcd", "dafdfasdf"}
	gWC.ipsCache["test"] = a
	log.Println(gWC)

}

func test2() {
	var NSans []string
	options := &Options{
		BaseResolvers: DefaultOptions.BaseResolvers,
		MaxRetries:    DefaultOptions.MaxRetries,
	}
	hostname := "viettel.vn"

	dnsMachineNormal, err := InitDNSFactory(options)

	if err != nil {
		log.Fatal(err)
	}

	NSans = dnsMachineNormal.getNSRecords(hostname)
	log.Println(NSans)

	dnsMachineOrigin, _ := InitDNSFactory(&Options{BaseResolvers: NSans})

	log.Println(dnsMachineOrigin.getARecords("abmetrix.viettel.vn"))

}

func test3() {
	gWC := &goWCModel{}
	gWC.init()
	processMassdnsCache("/tmp/ohdns.W5uy9chX/massdns.txt", &gWC.domainsQueue, &gWC.ipsCache)
	log.Println(gWC.domainsQueue)
	log.Println(gWC.ipsCache)
	d, _ := gWC.popDomain()
	log.Println(gWC.domainsQueue)

	options := &Options{
		BaseResolvers: DefaultOptions.BaseResolvers,
		MaxRetries:    DefaultOptions.MaxRetries,
	}
	dnsMachine, _ := InitDNSFactory(options)
	log.Println(dnsMachine.getCNAMERecords("360-security-antivirus-free.it.prod.cloud.netflix.com"))
	log.Println(dnsMachine.getCNAMERecords("abmetrix.netflix.com"))
	log.Println(dnsMachine.getCNAMERecords("wwccssfscs.netflix.com"))

	log.Println(gWC.resolve(d, dnsMachine))

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
		for _, Ip := range tmpDomainIps {
			addQueue(&gWC.knownWcResult, Ip, []string{rootDomainCheck}, knownWcMutex)
		}
		return true
	}

	return false
}

func main() {
	//test()
	//test2()
	//concurrency := 30

	test3()

	log.Println("Exited")

}
