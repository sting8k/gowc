package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"github.com/sting8k/gowc/cmd/model"
	"github.com/sting8k/gowc/cmd/processor"
	"github.com/sting8k/gowc/cmd/utils"
	"github.com/sting8k/gowc/pkg/dnshandler"
)

func craftOutput(gWC *model.GoWCModel) map[string][]string {

	output := make(map[string][]string)

	rootDomains := gWC.GetRootDomains()
	rootIPs := gWC.GetRootIPs()

	for domain := range gWC.IpsMap.IterBuffered() {
		for _, rD := range rootDomains {
			if strings.Contains(domain.Key, rD) && domain.Key != rD {
				newIPs := make([]string, 0)
				for _, iV := range domain.Val.([]string) {
					if !utils.StringInSlice(iV, rootIPs) {
						newIPs = append(newIPs, iV)
					}
				}
				gWC.IpsMap.Set(domain.Key, newIPs)
				break
			}
		}

		if v, _ := gWC.IpsMap.Get(domain.Key); len(v.([]string)) != 0 && !strings.HasPrefix(domain.Key, model.GeneratedMagicStr) {
			output[domain.Key] = v.([]string)
		}
	}

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

func CollectAnswer(gWC *model.GoWCModel, dnsMachine *dnshandler.DNSFactory) {
	for {
		select {
		case AnsData, more := <-dnsMachine.AnsMap:
			if !more {
				return
			}
			if ds, ok := gWC.IpsMap.Get(AnsData[0]); ok {
				tmp := append(ds.([]string), AnsData[1:]...)
				gWC.IpsMap.Set(AnsData[0], utils.RemoveDuplicates(tmp))
			} else {
				gWC.IpsMap.Set(AnsData[0], utils.RemoveDuplicates(AnsData[1:]))
			}

			v, _ := gWC.IpsMap.Get(AnsData[0])
			logrus.Debug("Added total new ", AnsData[0], v.([]string))
		default:
			continue
		}
	}
}

func ProcessDomain(domain string, gWC *model.GoWCModel, dnsMachine *dnshandler.DNSFactory) {
	ips, err := gWC.Resolve(domain, dnsMachine)
	if err != nil {
		gWC.DomainsChan <- domain
		return
	}
	if len(ips) == 0 {
		return
	}

	if gWC.IpIsWildcard(domain, ips[0]) {
		return
	}

	parentDomain := model.GetParentDomain(domain)
	tmpDomain := model.GeneratedMagicStr + "." + parentDomain
	tmpDomainIps, err := gWC.Resolve(tmpDomain, dnsMachine)
	if err != nil {
		gWC.DomainsChan <- domain
		return
	}

	if utils.StringInSlice(ips[0], tmpDomainIps) {
		rootDomainCheck, err := gWC.GetRootOfWildcard(domain, dnsMachine)
		if err != nil {
			gWC.DomainsChan <- domain
			return
		}
		for _, IP := range tmpDomainIps {
			model.AddQueue(&gWC.KnownWcResult, IP, []string{rootDomainCheck}, model.KnownWcMutex)
		}
	}

}

func Worker(gWC *model.GoWCModel, dnsMachine *dnshandler.DNSFactory, wg *sync.WaitGroup) {
	var domain string
	defer wg.Done()

	for len(gWC.DomainsChan) > 0 {
		select {
		case domain = <-gWC.DomainsChan:
			if domain != "" {
				ProcessDomain(domain, gWC, dnsMachine)
			}
		default:
			continue
		}
	}
}

type GoWcArgs struct {
	MassdnsCache string `short:"m" description:"Massdns output file" required:"true"`
	Domain       string `short:"d" long:"domain" description:"Domain of target" required:"true"`
	Threads      int    `short:"t" long:"threads" description:"Threads" default:"20"`
	Timeout      int    `short:"s" long:"timeout" description:"Timeout in seconds" default:"5"`
	Qps          int    `short:"q" long:"qps" description:"Queries per second" default:"10000"`
	MaxRetries   int    `short:"r" long:"retries" description:"Max retries each failed query" default:"1"`
	Output       string `short:"o" long:"output" description:"Output file"`
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
                         GoWC v1.3.5					
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
	// log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors: false,
		FullTimestamp: false,
	})
	logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.ErrorLevel)

	args := argsParse()

	//Get root NS of target
	NSans, _ := getNSOfTarget(args.Domain)
	fmt.Fprintf(os.Stderr, "[+] Nameserver list: \n\t+ %s\n", strings.Join(append(NSans, dnshandler.DefaultOptions.BaseResolvers...), "\n\t+ "))
	//Initialize gWC model
	dnsMachine, _ := dnshandler.InitDNSFactory(&dnshandler.Options{
		BaseResolvers: append(dnshandler.DefaultOptions.BaseResolvers, NSans...),
		MaxRetries:    args.MaxRetries,
		Qps:           args.Qps,
		Timeout:       args.Timeout},
	)

	gWC := &model.GoWCModel{}
	gWC.Init()
	gWC.SetMainDomain(args.Domain)

	processor.ProcessMassdnsCache(args.MassdnsCache, gWC)

	fmt.Fprintf(os.Stderr, "[+] Loaded %d subdomains in MassDns cache file.\n", gWC.IpsMap.Count())

	if !gWC.IpsMap.Has(gWC.MainDomain) {
		gWC.IpsMap.Set(gWC.MainDomain, dnsMachine.GreedyQuery(gWC.MainDomain, "A"))
	}

	start := time.Now()

	gWC.DomainsChan = make(chan string, gWC.IpsMap.Count()*2)
	for i := range gWC.SortedList {
		gWC.DomainsChan <- gWC.SortedList[i]
	}

	var wg sync.WaitGroup
	concurrency := args.Threads
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go Worker(gWC, dnsMachine, &wg)
	}

	go CollectAnswer(gWC, dnsMachine)
	go dnsMachine.ProcessPool(args.Timeout)

	go func() {
		time.Sleep(200 * time.Millisecond)
		progressLine := len(fmt.Sprintf("\r[i] Sent %d queries. %d subdomains remaining ...", dnsMachine.QueryCounter, len(gWC.DomainsChan)))
		// logrus.Debugf("On %d | %d | %d | %d \n", dnsMachine.QueryCounter, len(gWC.DomainsChan), len(gWC.KnownWcResult), runtime.NumGoroutine())
		for dnsMachine.QueryCounter != -1 {
			// logrus.Debugf("On %d | %d | %d | %d \n", dnsMachine.QueryCounter, len(gWC.DomainsChan), len(gWC.KnownWcResult), runtime.NumGoroutine())
			currentLine := fmt.Sprintf("\r[i] Sent %d queries. %d subdomains remaining ...", dnsMachine.QueryCounter, len(gWC.DomainsChan))
			padding := ""
			if progressLine-len(currentLine) > 0 {
				padding = strings.Repeat(" ", progressLine-len(currentLine))
			}
			fmt.Fprintf(os.Stderr, currentLine+padding)
			time.Sleep(5000 * time.Millisecond)
		}
	}()

	wg.Wait()

	fmt.Fprintf(os.Stderr, "\n[!] Sent %d queries. All subdomains resolved.\n", dnsMachine.QueryCounter)

	// Clean
	dnsMachine.KillSwitch <- true
	dnsMachine.StopResolveEngine()
	close(gWC.DomainsChan)

	fmt.Fprintln(os.Stderr, "\n[+] Wildcard domains:\n\t+", strings.Join(gWC.GetRootIPs(), "\n\t+ "))

	fmt.Fprintln(os.Stderr, "[i] Crafting output ...")
	output := craftOutput(gWC)
	elapsed := time.Since(start)
	validDomains := processor.ExportOutput(output, args.Output, args.WithIp)
	fmt.Fprintf(os.Stderr, "\n[!] Found %d valid subdomains in %s\n", validDomains, elapsed)
}
