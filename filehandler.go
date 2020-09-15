package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func processMassdnsCache(path string, domainsQueue *[]string, ipsCache *map[string][]string) {
	var tmpDomain, tmpIP string
	domains, _ := readLines(path) // x.y.z A 22.52.25.25

	for _, domain := range domains[:10] {
		pieces := strings.Split(domain, " ")
		if len(pieces) != 3 {
			continue
		}
		if pieces[1] != "CNAME" && pieces[1] != "A" && pieces[1] != "AAAA" {
			continue
		}
		tmpDomain = strings.TrimSuffix(pieces[0], ".")
		tmpIP = strings.TrimSuffix(pieces[2], ".")
		*domainsQueue = append(*domainsQueue, tmpDomain)
		(*ipsCache)[tmpDomain] = append((*ipsCache)[tmpDomain], tmpIP)
	}
	*domainsQueue = RemoveDuplicates(*domainsQueue)

}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
