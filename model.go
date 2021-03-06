package main

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/sting8k/gowc/dnshandler"
	"github.com/sting8k/gowc/utils"

	"github.com/rs/xid"
)

var GeneratedMagicStr = xid.New().String()
var ipsMutex = &sync.RWMutex{}
var knownWcMutex = &sync.RWMutex{}
var resolverMutex = &sync.Mutex{}
var domainQueueMutex = &sync.Mutex{}
var counter = 0

type goWCModel struct {
	ipsCache      map[string][]string
	knownWcResult map[string][]string
	resolveQueue  map[string]bool
	nsRecord      []string
	domainsQueue  []string
}

func (m *goWCModel) init() {
	m.ipsCache = make(map[string][]string)
	m.knownWcResult = make(map[string][]string)
	m.nsRecord = make([]string, 0)
	m.domainsQueue = make([]string, 0)
	m.resolveQueue = make(map[string]bool, 0)
}

func (m *goWCModel) popDomain() (string, error) {
	var result string

	if len(m.domainsQueue) == 0 {
		return "", errors.New("no more element")
	}
	result = m.domainsQueue[0]
	defer domainQueueMutex.Unlock()
	domainQueueMutex.Lock()
	m.domainsQueue = m.domainsQueue[1:]
	return result, nil
}

func (m *goWCModel) removeResolveQueue(domain string) {
	defer resolverMutex.Unlock()
	resolverMutex.Lock()
	delete(m.resolveQueue, domain)
}

func (m *goWCModel) resolve(domain string, dnsMachine *dnshandler.DNSFactory) []string {
	toBeResolved := false
	ipsMutex.Lock()

	if _, flag1 := m.ipsCache[domain]; flag1 != true {
		resolverMutex.Lock()
		if _, flag2 := m.resolveQueue[domain]; flag2 != true {
			m.resolveQueue[domain] = true
			toBeResolved = true
		}
		resolverMutex.Unlock()
	}
	ipsMutex.Unlock()

	if toBeResolved {
		ips := dnsMachine.Query(domain, "A")
		ips = append(ips, dnsMachine.Query(domain, "CNAME")...)
		AddQueue(&m.ipsCache, domain, ips, ipsMutex)
		m.removeResolveQueue(domain)
	} else {
		_, ok := m.resolveQueue[domain]
		for ok {
			ok = m.resolveQueue[domain]
			time.Sleep(50 * time.Millisecond)
		}
	}

	defer ipsMutex.Unlock()
	ipsMutex.Lock()
	return m.ipsCache[domain]
}

func (m *goWCModel) ipIsWildcard(domain, ip string) bool {
	defer knownWcMutex.Unlock()
	knownWcMutex.Lock()
	if _, ok := m.knownWcResult[ip]; ok {
		for wcIP := range m.knownWcResult {
			for _, rootDomainGot := range m.knownWcResult[wcIP] {
				if strings.HasSuffix(domain, "."+rootDomainGot) {
					return true
				}
			}
		}
	}
	return false
}

func (m *goWCModel) IsRootOf(domain, tmpRoot string, dnsMachine *dnshandler.DNSFactory) bool {
	parentDomain := GetParentDomain(domain)
	tmpDomain := GeneratedMagicStr + "." + parentDomain
	tmpDomainIps := m.resolve(tmpDomain, dnsMachine)

	tmpParent := GeneratedMagicStr + "." + GetParentDomain(tmpRoot)
	tmpParentIps := m.resolve(tmpParent, dnsMachine)

	if utils.StringInSlice(tmpDomainIps[0], tmpParentIps) {
		return true
	}
	return false
}

func (m *goWCModel) getRootOfWildcard(domain string, dnsMachine *dnshandler.DNSFactory) string {
	tmpRoot := ""
	domainPieces := strings.Split(domain, ".")
	root := domain
	for i := len(domainPieces) - 1; i > 0; i-- {
		tmpRoot = strings.Join(domainPieces[i-1:len(domainPieces)], ".")
		if m.IsRootOf(domain, tmpRoot, dnsMachine) {
			break
		}
		root = tmpRoot
	}
	return root
}

func (m *goWCModel) getRootDomains() map[string]bool {
	rootDomains := make(map[string]bool)
	for ip := range m.knownWcResult {
		for _, domain := range m.knownWcResult[ip] {
			rootDomains[domain] = true
		}
	}
	return rootDomains
}

func GetParentDomain(s string) string {
	return strings.Join(strings.Split(s, ".")[1:], ".")
}

func AddQueue(q *map[string][]string, key string, values []string, mutex *sync.RWMutex) {
	defer mutex.Unlock()
	mutex.Lock()
	if _, ok := (*q)[key]; ok != true {
		(*q)[key] = []string{}
	}
	for _, value := range values {
		if utils.StringInSlice(value, (*q)[key]) != true {
			(*q)[key] = append((*q)[key], value)
		}
	}
}

func RemoveQueue(q *map[string][]string, key string, mutex *sync.Mutex) {
	defer mutex.Unlock()
	mutex.Lock()
	delete(*q, key)
}
