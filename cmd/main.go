package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/sting8k/gowc/cmd/model"
	"github.com/sting8k/gowc/cmd/processor"
	"github.com/sting8k/gowc/cmd/utils"
	"github.com/sting8k/gowc/pkg/dnshandler"
)

type GoWcArgsx struct {
	MassdnsCache string
	Domain       string
	Timeout      int
	Qps          int
	Output       string
	WithIp       bool
}

func craftOutput(gWC *model.GoWCModel) map[string][]string {

	output := make(map[string][]string)
	var idx int
	var ok bool

	rootDomains := gWC.GetRootDomains()
	rootIPs := gWC.GetRootIPs()

	for domain := range gWC.IpsCache {
		for _, rD := range rootDomains {
			if strings.Contains(domain, rD) && domain != rD {
				for _, rI := range rootIPs {
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
	// fmt.Println(gWC.KnownWcResult)
	return output
}

func getNSOfTarget(domain string) ([]string, error) {
	var NSans []string
	options := &dnshandler.Options{
		BaseResolvers: dnshandler.DefaultOptions.BaseResolvers,
		MaxRetries:    dnshandler.DefaultOptions.MaxRetries,
		Qps:           1,
	}
	Resolvers := dnshandler.DefaultOptions.BaseResolvers

	dnsMachineNormal, err := dnshandler.InitDNSFactory(options)

	if err != nil {
		log.Fatal(err)
	}

	NSans = dnsMachineNormal.GreedyQuery(domain, "NS")
	if len(NSans) != 0 {
		return NSans, nil
	}

	return Resolvers, errors.New("empty NS")
}

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

	if domain == "" {
		fmt.Println("Debug", parentDomain, tmpDomain, tmpDomainIps, "| IPs[0]", ips)
	}

	if utils.StringInSlice(ips[0], tmpDomainIps) {
		rootDomainCheck := strings.ToLower(gWC.GetRootOfWildcard(domain))
		for _, IP := range tmpDomainIps {
			model.AddQueue(&gWC.KnownWcResult, IP, []string{rootDomainCheck}, model.KnownWcMutex)
			// fmt.Println("Key:", len(gWC.DomainsQueue), "| Wildcard domain:", domain, "|", rootDomainCheck, IP, gWC.KnownWcResult)
			// utils.Stdinput()
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
	for _, domain := range gWC.DomainsQueue {
		if domain != "" {
			ResolveNewDomains(domain, gWC, dnsMachine)
		}
	}

	// Ask A Records
	dnsMachine.PrepareQueryPool()
	fmt.Fprintf(os.Stderr, "[+] Testing %d subdomains ...\n", len(dnsMachine.QueryDict))
	for i := range dnsMachine.QueryDict {
		fmt.Println(i)
	}
	ResolvedRecords := dnsMachine.ProcessPool(timeout)

	// for d := range ResolvedARecords {
	// 	delete(dnsMachine.QueryDict, d)
	// }
	fmt.Println("")

	// Import Records
	for dm, ips := range ResolvedRecords {
		model.AddQueue(&gWC.IpsCache, dm, ips, model.IpsMutex)
	}

	dnsMachine.StopPool()
	fmt.Println("")

	fmt.Fprintln(os.Stderr, "[i] Cleaning wildcards ...", len(gWC.DomainsQueue))
	for d := range gWC.IpsCache {
		gWC.IpsCache[d] = utils.RemoveDuplicates(gWC.IpsCache[d])
	}

	sort.Slice(gWC.DomainsQueue, func(i, j int) bool {
		return len(gWC.DomainsQueue[i]) < len(gWC.DomainsQueue[j])
	})

	for len(gWC.DomainsQueue) > 0 {
		if len(gWC.DomainsQueue)%500 == 0 {
			fmt.Printf("\rOn %d", len(gWC.DomainsQueue))
		}
		domain, _ = gWC.PopDomain()
		if domain != "" {
			CleanWildcards(domain, gWC)
		}
	}
	fmt.Println("")
	fmt.Println(gWC.KnownWcResult)
}

type GoWcArgs struct {
	MassdnsCache string `short:"m" description:"Massdns output file" required:"true"`
	Domain       string `short:"d" description:"Domain of target" required:"true"`
	Timeout      int    `short:"s" long:"timeout" description:"Timeout in seconds" default:"10"`
	Qps          int    `short:"q" long:"qps" description:"Queries per second" default:"10000"`
	MaxRetries   int    `short:"r" long:"retries" description:"Max retries each failed query" default:"1"`
	Output       string `short:"o" description:"Output file"`
	WithIp       bool   `short:"i" long:"ip" description:"Output with ips from massdns"`
}

var gowcArgs GoWcArgs

// *GoWcArgs
func argsParse() *GoWcArgs {
	banner := `
 ██████╗  ██████╗ ██╗    ██╗ ██████╗
██╔════╝ ██╔═══██╗██║    ██║██╔════╝
██║  ███╗██║   ██║██║ █╗ ██║██║     
██║   ██║██║   ██║██║███╗██║██║     
╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗
 ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝
                           GoWC v1.3					
`
	fmt.Fprint(os.Stderr, banner)
	_, err := flags.Parse(&gowcArgs)

	if err != nil {
		flagError := err.(*flags.Error)
		if flagError.Type == flags.ErrHelp {
			// user asked for help on flags.
			// program can exit successfully
			os.Exit(0)
		}
		if flagError.Type == flags.ErrUnknownFlag {
			fmt.Println("Use --help to view all available options.")
			os.Exit(1)
		}
		// fmt.Printf("Error parsing flags: %s\n", err)
		os.Exit(1)
	}
	return &gowcArgs
}

func main() {
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	args := argsParse()
	// concurrency := args.Threads

	//Get root NS of target
	NSans, _ := getNSOfTarget(args.Domain)
	fmt.Fprintf(os.Stderr, "[+] Nameserver list: %q\n", append(NSans, dnshandler.DefaultOptions.BaseResolvers...))
	//Initialize gWC model
	dnsMachine, _ := dnshandler.InitDNSFactory(&dnshandler.Options{
		BaseResolvers: append(dnshandler.DefaultOptions.BaseResolvers, NSans...),
		MaxRetries:    args.MaxRetries,
		Qps:           args.Qps},
	)

	gWC := &model.GoWCModel{}
	gWC.Init()
	gWC.SetMainDomain(args.Domain)
	//Processing

	processor.ProcessMassdnsCache(args.MassdnsCache, &gWC.DomainsQueue, &gWC.IpsCache)
	fmt.Fprintf(os.Stderr, "[+] Loaded %d subdomains in MassDns cache file.\n", len(gWC.DomainsQueue))

	if _, ok := gWC.IpsCache[gWC.MainDomain]; !ok {
		gWC.IpsCache[gWC.MainDomain] = dnsMachine.GreedyQuery(gWC.MainDomain, "A")
	}

	start := time.Now()
	Worker(gWC, dnsMachine, args.Timeout)

	elapsed := time.Since(start)
	fmt.Fprintln(os.Stderr, "[i] Crafting output ...")
	output := craftOutput(gWC)
	validDomains := processor.ExportOutput(output, args.Output, args.WithIp)
	fmt.Fprintf(os.Stderr, "[!] Found %d valid subdomains in %s\n", validDomains, elapsed)
}
