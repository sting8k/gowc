package model

import (
	"errors"
	"strings"
	"sync"

	"github.com/sting8k/gowc/cmd/utils"
	"github.com/sting8k/gowc/pkg/dnshandler"

	"github.com/rs/xid"
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
}

func (m *GoWCModel) Init() {
	m.IpsCache = make(map[string][]string)
	m.KnownWcResult = make(map[string][]string)
	m.NsRecord = make([]string, 0)
	m.DomainsQueue = make([]string, 0)
	m.ResolveQueue = make(map[string]bool, 0)
}

func (m *GoWCModel) SetMainDomain(mdm string) {
	m.MainDomain = strings.ToLower(mdm)
}

func (m *GoWCModel) PopDomain() (string, error) {
	var result string
	// defer DomainQueueMutex.Unlock()
	// DomainQueueMutex.Lock()

	if len(m.DomainsQueue) == 0 {
		return "", errors.New("no more element")
	}
	// if len(m.DomainsQueue)%100 == 0 {
	// 	fmt.Println("Remaining:", len(m.DomainsQueue))
	// }
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

func (m *GoWCModel) Resolve(domain string, dnsMachine *dnshandler.DNSFactory) []string {
	toBeResolved := false
	IpsMutex.Lock()

	if _, flag1 := m.IpsCache[domain]; !flag1 {
		resolverMutex.Lock()
		if _, flag2 := m.ResolveQueue[domain]; !flag2 {
			m.ResolveQueue[domain] = true
			toBeResolved = true
		}
		resolverMutex.Unlock()
	}
	IpsMutex.Unlock()

	if toBeResolved {
		// fmt.Println("Resolving", domain)
		ips := dnsMachine.GreedQuery(domain, "A")
		ips = append(ips, dnsMachine.GreedQuery(domain, "CNAME")...)
		AddQueue(&m.IpsCache, domain, ips, IpsMutex)
		m.RemoveResolveQueue(domain)
	} else {
		resolverMutex.Lock()
		_, ok := m.ResolveQueue[domain]
		resolverMutex.Unlock()
		for ok {
			resolverMutex.Lock()
			ok = m.ResolveQueue[domain]
			resolverMutex.Unlock()
			// time.Sleep(50 * time.Millisecond)
		}
	}

	defer IpsMutex.Unlock()
	IpsMutex.Lock()
	return m.IpsCache[domain]
}

func (m *GoWCModel) PushToResolvePool(domain string, dnsMachine *dnshandler.DNSFactory) {
	if !strings.HasSuffix(domain, m.MainDomain) {
		return
	}
	if _, ok := m.IpsCache[domain]; !ok {
		if _, ok := dnsMachine.QueryDict[domain]; !ok {
			dnsMachine.QueryDict[domain] = struct{}{}
		}
	}
}

func (m *GoWCModel) IpIsWildcard(domain, ip string) bool {
	// defer KnownWcMutex.Unlock()
	// KnownWcMutex.Lock()
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

func (m *GoWCModel) IsRootOf_old(domain, tmpRoot string, dnsMachine *dnshandler.DNSFactory) bool {
	parentDomain := GetParentDomain(domain)
	tmpDomain := GeneratedMagicStr + "." + parentDomain
	tmpDomainIps := m.Resolve(tmpDomain, dnsMachine)

	tmpParent := GeneratedMagicStr + "." + GetParentDomain(tmpRoot)
	tmpParentIps := m.Resolve(tmpParent, dnsMachine)

	return utils.StringInSlice(tmpDomainIps[0], tmpParentIps)
}

func (m *GoWCModel) GetRootOfWildcard_old(domain string, dnsMachine *dnshandler.DNSFactory) string {
	tmpRoot := ""
	domainPieces := strings.Split(domain, ".")
	root := domain
	for i := len(domainPieces) - 1; i > 0; i-- {
		tmpRoot = strings.Join(domainPieces[i-1:], ".")
		if m.IsRootOf_old(domain, tmpRoot, dnsMachine) {
			break
		}
		root = tmpRoot
	}
	return root
}

func (m *GoWCModel) IsRootOf(domain, tmpRoot string) bool {
	parentDomain := GetParentDomain(domain)
	tmpDomain := GeneratedMagicStr + "." + parentDomain
	tmpDomainIps := m.GetIpsFromCache(tmpDomain)

	tmpParent := GeneratedMagicStr + "." + GetParentDomain(tmpRoot)
	tmpParentIps := m.GetIpsFromCache(tmpParent)

	return utils.StringInSlice(tmpDomainIps[0], tmpParentIps)
}

func (m *GoWCModel) GetRootOfWildcard(domain string) string {
	tmpRoot := ""
	domainPieces := strings.Split(domain, ".")
	root := domain
	for i := len(domainPieces) - 1; i > 0; i-- {
		tmpRoot = strings.ToLower(strings.Join(domainPieces[i-1:], "."))
		if m.IsRootOf(domain, tmpRoot) {
			break
		}
		root = tmpRoot
	}
	return root
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
	parentDomain := GetParentDomain(domain)
	tmpDomain := GeneratedMagicStr + "." + parentDomain
	m.PushToResolvePool(tmpDomain, dnsMachine)
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

	(*q)[key] = append((*q)[key], values...)
	(*q)[key] = utils.RemoveDuplicates((*q)[key])
}

func RemoveQueue(q *map[string][]string, key string, mutex *sync.Mutex) {
	defer mutex.Unlock()
	mutex.Lock()
	delete(*q, key)
}
