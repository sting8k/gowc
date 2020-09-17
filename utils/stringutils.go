package utils

import (
	"regexp"
	"strings"
)

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func StringInSliceWithIndex(a string, list []string) (bool, int) {
	for i, b := range list {
		if b == a {
			return true, i
		}
	}
	return false, -1
}

func RemoveDuplicates(s []string) []string {

	encountered := make(map[string]struct{})
	result := make([]string, 0)
	//duplicate := make([]string, 0)
	for _, v := range s {
		if _, ok := encountered[v]; ok {
			//duplicate = append(duplicate, v)
			continue
		} else {
			encountered[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

func RemoveIndex(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

func CNAMEparse(str string) string {
	r := regexp.MustCompile("[^\\s]+")
	pieces := r.FindAllString(str, -1)
	result := pieces[len(pieces)-1]
	result = strings.TrimSpace(strings.TrimSuffix(result, "."))
	return result
}

func NSparse(str string) string {
	pieces := strings.Split(str, "NS")
	result := pieces[len(pieces)-1]
	result = strings.TrimSpace(strings.TrimSuffix(result, "."))
	return result
}

func ValidateNSFmt(str string) string {
	r := str
	if strings.HasSuffix(str, ":53") != true {
		r = str + ":53"
	}
	return r
}
