package processor

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sting8k/gowc/cmd/model"
	"github.com/sting8k/gowc/cmd/utils"
)

func ProcessMassdnsCache(path string, gWC *model.GoWCModel) {
	var tmpDomain, tmpIP string
	lines, _ := utils.ReadLines(path) // x.y.z A 22.52.25.25
	tmpMap := make(map[string][]string, 0)
	for _, domain := range lines {
		pieces := strings.Split(domain, " ")
		if len(pieces) != 3 {
			continue
		}
		if pieces[1] != "CNAME" && pieces[1] != "A" && pieces[1] != "AAAA" {
			continue
		}
		tmpDomain = strings.ToLower(strings.TrimSuffix(pieces[0], "."))
		tmpIP = strings.TrimSuffix(pieces[2], ".")
		gWC.SortedList = append(gWC.SortedList, tmpDomain)
		tmpMap[tmpDomain] = append(tmpMap[tmpDomain], tmpIP)
	}

	gWC.SortedList = utils.RemoveDuplicates(gWC.SortedList)

	sort.Slice(gWC.SortedList, func(i, j int) bool {
		return len(strings.Split(gWC.SortedList[i], ".")) < len(strings.Split(gWC.SortedList[j], "."))
	})

	for d := range tmpMap {
		gWC.IpsMap.Set(d, utils.RemoveDuplicates(tmpMap[d]))
	}
}

func ExportOutput(data map[string][]string, path string, withip bool) int {
	var output []string
	for d := range data {
		if withip {
			output = append(output, d+" ["+strings.Join(data[d], ", ")+"]")
		} else {
			output = append(output, d)
		}

	}
	sort.Strings(output)

	if path != "" {
		fmt.Fprintln(os.Stderr, "[i] Saving output to file: "+path)
		utils.WriteLines(output, path)
	} else {
		for _, line := range output {
			fmt.Println(line)
		}
	}
	return len(output)
}
