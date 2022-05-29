package processor

import (
	"strings"

	"github.com/sting8k/gowc/cmd/utils"
)

func ProcessMassdnsCache(path string, domainsQueue *[]string, IpsCache *map[string][]string) {
	var tmpDomain, tmpIP string
	domains, _ := utils.ReadLines(path) // x.y.z A 22.52.25.25
	for _, domain := range domains {
		pieces := strings.Split(domain, " ")
		if len(pieces) != 3 {
			continue
		}
		if pieces[1] != "CNAME" && pieces[1] != "A" && pieces[1] != "AAAA" {
			continue
		}
		tmpDomain = strings.ToLower(strings.TrimSuffix(pieces[0], "."))
		tmpIP = strings.TrimSuffix(pieces[2], ".")
		*domainsQueue = append(*domainsQueue, tmpDomain)
		(*IpsCache)[tmpDomain] = append((*IpsCache)[tmpDomain], tmpIP)
	}
	*domainsQueue = utils.RemoveDuplicates(*domainsQueue)
}
