package utils

import (
	"regexp"
	"strings"
)

var rp = regexp.MustCompile("[^\\s]+")

func IntInSlice(a uint16, list []uint16) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if len(b) == len(a) && b == a { //list[i] == a
			return true
		}
	}
	return false
}

func StringInSliceWithIndex(a string, list []string) (bool, int) {
	for i := range list {
		if list[i] == a {
			return true, i
		}
	}
	return false, -1
}

func RemoveDuplicates(s []string) []string {

	encountered := make(map[string]struct{})
	result := make([]string, 0)
	for _, v := range s {
		if _, ok := encountered[v]; ok {
			continue
		} else {
			encountered[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

func RemoveIndex(slice []string, index int) []string {
	// return append(slice[:index], slice[index+1:]...)
	sliceLen := len(slice)
	sliceLastIndex := sliceLen - 1

	if index != sliceLastIndex {
		slice[index] = slice[sliceLastIndex]
	}

	return slice[:sliceLastIndex]
}

func CNAMEparse(str string) string {
	pieces := rp.FindAllString(str, -1)
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
	if !strings.HasSuffix(str, ":53") {
		r = str + ":53"
	}
	return r
}
