package model

import (
	"errors"
	"sort"
	"strings"
	"sync"

	cmap "github.com/orcaman/concurrent-map"
	"github.com/rs/xid"
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
	KnownWcResult map[string][]string
	NsRecord      []string
	SortedList    []string
	DomainsChan   chan string
	IpsMap        cmap.ConcurrentMap
}

func (m *GoWCModel) Init() {
	m.KnownWcResult = make(map[string][]string)
	m.NsRecord = make([]string, 0)
	m.SortedList = make([]string, 0)
	m.IpsMap = cmap.New()

}

func (m *GoWCModel) SetMainDomain(mdm string) {
	m.MainDomain = strings.ToLower(mdm)
}

func (m *GoWCModel) Resolve(domain string, dnsMachine *dnshandler.DNSFactory) ([]string, error) {
	flagx := false
	if !strings.HasSuffix(domain, m.MainDomain) {
		return []string{}, nil
	}

	if !m.IpsMap.Has(domain) {
		resolverMutex.Lock()
		if _, flag2 := dnsMachine.QueryDict[domain]; !flag2 {
			dnsMachine.QueryDict[domain] = struct{}{}
			flagx = true
		}
		resolverMutex.Unlock()

		if flagx {
			dnsMachine.QueryPool <- domain
		}
		// logrus.Error(domain, " waiting for resolve")
		return nil, errors.New("waiting for resolve")

	} else {
		v, _ := m.IpsMap.Get(domain)
		return v.([]string), nil
	}

}

func (m *GoWCModel) PushToResolvePool(domain string, dnsMachine *dnshandler.DNSFactory) {
	if !strings.HasSuffix(domain, m.MainDomain) {
		return
	}
	if _, ok := m.IpsMap.Get(domain); !ok {
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
				if len(domain) > len(rootDomainGot)+1 && strings.HasSuffix(domain, "."+rootDomainGot) {
					return true
				}
			}
		}
	}
	return false
}

func (m *GoWCModel) GetRootOfWildcard(domain string, dnsMachine *dnshandler.DNSFactory) (string, error) {
	tmpRoot := ""
	domainPieces := strings.Split(domain, ".")

	root := domain

	for i := len(domainPieces) - 1; i > 0; i-- {
		tmpRoot = strings.ToLower(strings.Join(domainPieces[i-1:], "."))
		isWc, err := m.IsWildcardRoot(domain, tmpRoot, dnsMachine)
		if err != nil {
			return "", err
		}
		if isWc {
			break
		}
		root = tmpRoot
	}
	return root, nil
}

func (m *GoWCModel) IsWildcardRoot(domain, tmpRoot string, dnsMachine *dnshandler.DNSFactory) (bool, error) {
	parentDomain := GetParentDomain(domain)
	tmpDomain := GeneratedMagicStr + "." + parentDomain
	tmpDomainIps, err := m.Resolve(tmpDomain, dnsMachine)
	if err != nil {
		return false, err
	}

	tmpParent := GeneratedMagicStr + "." + GetParentDomain(tmpRoot)
	tmpParentIps, err := m.Resolve(tmpParent, dnsMachine)
	if err != nil {
		return false, err
	}

	return utils.StringInSlice(tmpDomainIps[0], tmpParentIps), nil
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

	(*q)[key] = append((*q)[key], values...)
	(*q)[key] = utils.RemoveDuplicates((*q)[key])
	if len((*q)[key])%10 == 0 {
		sort.Slice((*q)[key], func(i, j int) bool {
			return len((*q)[key][i]) < len((*q)[key][j])
		})
	}
}

func RemoveQueue(q *map[string][]string, key string, mutex *sync.Mutex) {
	defer mutex.Unlock()
	mutex.Lock()
	delete(*q, key)
}
