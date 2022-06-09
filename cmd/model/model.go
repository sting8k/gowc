package model

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	cmap "github.com/orcaman/concurrent-map"
	"github.com/rs/xid"
	"github.com/sirupsen/logrus"
	"github.com/sting8k/gowc/cmd/utils"
	"github.com/sting8k/gowc/pkg/dnshandler"
)

var GeneratedMagicStr = xid.New().String()
var IpsMutex = &sync.RWMutex{}
var KnownWcMutex = &sync.RWMutex{}
var resolverMutex = &sync.Mutex{}
var DomainQueueMutex = &sync.Mutex{}

type GoWCModel struct {
	MainDomain    string
	IpsCache      map[string][]string
	KnownWcResult map[string][]string
	ResolveQueue  map[string]bool
	NsRecord      []string
	DomainsQueue  []string
	IpsMap        cmap.ConcurrentMap
}

func (m *GoWCModel) Init() {
	m.IpsCache = make(map[string][]string)
	m.KnownWcResult = make(map[string][]string)
	m.NsRecord = make([]string, 0)
	m.DomainsQueue = make([]string, 0)
	m.ResolveQueue = make(map[string]bool, 0)
	m.IpsMap = cmap.New()

}

func (m *GoWCModel) SetMainDomain(mdm string) {
	m.MainDomain = strings.ToLower(mdm)
}

func (m *GoWCModel) PopDomain() (string, error) {
	var result string
	defer DomainQueueMutex.Unlock()
	DomainQueueMutex.Lock()

	if len(m.DomainsQueue) == 0 {
		return "", errors.New("no more element")
	}
	result = m.DomainsQueue[0]
	m.DomainsQueue = m.DomainsQueue[1:]
	return result, nil
}

func (m *GoWCModel) RemoveResolveQueue(domain string) {
	defer resolverMutex.Unlock()
	resolverMutex.Lock()
	delete(m.ResolveQueue, domain)
}

func (m *GoWCModel) GetIpsFromCache(domain string) []string {
	if ips, ok := m.IpsCache[domain]; ok {
		return ips
	}
	return []string{}
}

func ToSliceOfAny[T any](s []T) []any {
	result := make([]any, len(s))
	for i, v := range s {
		result[i] = v
	}
	return result
}

func (m *GoWCModel) Resolve(domain string, dnsMachine *dnshandler.DNSFactory) []string {

	// If domain need to be pushed in QueryDict
	// logrus.Debug("Wait for", domain)
	flagx := false
	if !strings.HasSuffix(domain, m.MainDomain) {
		return []string{}
	}

	if !m.IpsMap.Has(domain) {
		resolverMutex.Lock()
		if _, flag2 := dnsMachine.QueryDict[domain]; !flag2 {
			dnsMachine.QueryDict[domain] = struct{}{}
			flagx = true
		}
		resolverMutex.Unlock()

		if flagx {
			logrus.Debug("Wait for ", domain)
			dnsMachine.QueryPool <- domain
		}

		counter := 0
		for {
			counter += 1
			if counter%10000000 == 0 {
				logrus.Debug("Ket r ", domain, " ", m.IpsMap.Has(domain))
			}
			if v, ok := m.IpsMap.Get(domain); ok {
				logrus.Debug("Wait done x ", domain, " ", v)
				return v.([]string)
			}
		}
	} else {
		v, _ := m.IpsMap.Get(domain)
		logrus.Debug("Wait done y", domain, " ", v)
		return v.([]string)
	}

}

func (m *GoWCModel) Resolve1(domain string, dnsMachine *dnshandler.DNSFactory) []string {

	IpsMutex.RLock()
	// If domain need to be pushed in QueryDict
	if _, flag1 := m.IpsCache[domain]; !flag1 {
		resolverMutex.Lock()
		if _, flag2 := dnsMachine.QueryDict[domain]; !flag2 {
			dnsMachine.QueryDict[domain] = struct{}{}
			dnsMachine.QueryPool <- domain
		}
		resolverMutex.Unlock()
		IpsMutex.RUnlock()
	} else {
		return m.IpsCache[domain]
	}

	fmt.Println("Wait for", domain)

	for {
		IpsMutex.RLock()
		if _, ok := m.IpsCache[domain]; ok {
			IpsMutex.RUnlock()
			fmt.Println("Wait done", domain)
			return m.IpsCache[domain]
		}
		IpsMutex.RUnlock()
	}

	// IpsMutex.RUnlok()

	// Wait to Fetch Answer

	// AddQueue(&m.IpsCache, domain, ips, IpsMutex)
	// fmt.Println("Resolving", domain)
	// ips := dnsMachine.GreedyQuery(domain, "A")
	// ips = append(ips, dnsMachine.GreedyQuery(domain, "CNAME")...)

	// return m.IpsCache[domain]
}

func (m *GoWCModel) PushToResolvePool(domain string, dnsMachine *dnshandler.DNSFactory) {
	if !strings.HasSuffix(domain, m.MainDomain) {
		return
	}
	if _, ok := m.IpsCache[domain]; !ok {
		if _, inDict := dnsMachine.QueryDict[domain]; !inDict {
			dnsMachine.QueryDict[domain] = struct{}{}
		}
	}
}

func (m *GoWCModel) IpIsWildcard(domain, ip string) bool {
	defer KnownWcMutex.RUnlock()
	KnownWcMutex.RLock()
	if _, ok := m.KnownWcResult[ip]; ok {
		for wcIP := range m.KnownWcResult {
			for _, rootDomainGot := range m.KnownWcResult[wcIP] {
				if strings.HasSuffix(domain, "."+rootDomainGot) {
					return true
				}
			}
		}
	}
	return false
}

func (m *GoWCModel) GetRootOfWildcardv3(domain string, dnsMachine *dnshandler.DNSFactory) string {
	tmpRoot := ""
	domainPieces := strings.Split(domain, ".")

	root := domain

	for i := len(domainPieces) - 1; i > 0; i-- {
		tmpRoot = strings.ToLower(strings.Join(domainPieces[i-1:], "."))
		logrus.Debug("tmpRoot:", tmpRoot)
		if m.IsWildcardRootv3(domain, tmpRoot, dnsMachine) {
			logrus.Debug(tmpRoot, "is root of", domain)
			break
		}
		logrus.Debug(tmpRoot, "is not root of", domain)
		root = tmpRoot
	}
	logrus.Debug("Final - root: ", root)
	return root
}

func (m *GoWCModel) IsWildcardRootv3(domain, tmpRoot string, dnsMachine *dnshandler.DNSFactory) bool {
	parentDomain := GetParentDomain(domain)
	tmpDomain := GeneratedMagicStr + "." + parentDomain
	tmpDomainIps := m.Resolve(tmpDomain, dnsMachine)

	tmpParent := GeneratedMagicStr + "." + GetParentDomain(tmpRoot)
	tmpParentIps := m.Resolve(tmpParent, dnsMachine)

	return utils.StringInSlice(tmpDomainIps[0], tmpParentIps)
}

func (m *GoWCModel) GetRootOfWildcard(domain string) string {
	tmpRoot := ""
	domainPieces := strings.Split(domain, ".")

	root := domain

	for i := len(domainPieces) - 1; i > 0; i-- {
		tmpRoot = strings.ToLower(strings.Join(domainPieces[i-1:], "."))
		fmt.Println("tmpRoot:", tmpRoot)
		if m.IsWildcardRoot(tmpRoot, domain) {
			fmt.Println(tmpRoot, "is root of", domain)
			break
		}
		fmt.Println(tmpRoot, "is not root of", domain)
		root = tmpRoot
	}
	fmt.Println("Final - root: ", root)
	return root
}

func (m *GoWCModel) IsWildcardRoot(tmpRoot, domain string) bool {
	parentDomain := GetParentDomain(domain)

	tmpDomain := GeneratedMagicStr + "." + parentDomain
	tmpDomainIps := m.GetIpsFromCache(tmpDomain)

	tmpParent := GeneratedMagicStr + "." + GetParentDomain(tmpRoot)
	tmpParentIps := m.GetIpsFromCache(tmpParent)

	return utils.StringInSlice(tmpDomainIps[0], tmpParentIps)
}

func (m *GoWCModel) ResolveRootOfWildcard(domain string, dnsMachine *dnshandler.DNSFactory) {
	tmpRoot := ""
	domainPieces := strings.Split(domain, ".")
	for i := len(domainPieces) - 1; i > 0; i-- {
		tmpRoot = strings.Join(domainPieces[i-1:], ".")
		m.ResolveRoot(domain, tmpRoot, dnsMachine)
	}
}

func (m *GoWCModel) ResolveRoot(domain, tmpRoot string, dnsMachine *dnshandler.DNSFactory) {
	tmpParent := GeneratedMagicStr + "." + GetParentDomain(tmpRoot)
	m.PushToResolvePool(tmpParent, dnsMachine)
}

func (m *GoWCModel) GetRootDomains() []string {
	rootDomains := make([]string, 0)
	for ip := range m.KnownWcResult {
		rootDomains = append(rootDomains, m.KnownWcResult[ip]...)
	}
	return utils.RemoveDuplicates(rootDomains)
}

func (m *GoWCModel) GetRootIPs() []string {
	rootIPs := make([]string, 0)
	for ip := range m.KnownWcResult {
		rootIPs = append(rootIPs, ip)
	}
	return utils.RemoveDuplicates(rootIPs)
}

func GetParentDomain(s string) string {
	return strings.Join(strings.Split(s, ".")[1:], ".")
}

func AddQueue(q *map[string][]string, key string, values []string, mutex *sync.RWMutex) {
	defer mutex.Unlock()
	mutex.Lock()
	if _, ok := (*q)[key]; !ok {
		(*q)[key] = []string{}
	}

	// for _, value := range values {
	// 	if !utils.StringInSlice(value, (*q)[key]) {

	// 	}
	// }

	(*q)[key] = append((*q)[key], values...)
	(*q)[key] = utils.RemoveDuplicates((*q)[key])
}

func RemoveQueue(q *map[string][]string, key string, mutex *sync.Mutex) {
	defer mutex.Unlock()
	mutex.Lock()
	delete(*q, key)
}
