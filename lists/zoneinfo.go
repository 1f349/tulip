package lists

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var (
	zoneDirs = []string{
		// Update path according to your OS
		"/usr/share/zoneinfo/",
		"/usr/share/lib/zoneinfo/",
		"/usr/lib/locale/TZ/",
	}
	zoneInfoOnce sync.Once
	zoneNames    []string
)

func ListZoneInfo() []string {
	zoneInfoOnce.Do(func() {
		zoneNames = make([]string, 0)
		for _, zoneDir := range zoneDirs {
			zoneNames = append(zoneNames, FindTimeZoneFiles(zoneDir)...)
		}
		sort.Strings(zoneNames)
	})
	return zoneNames
}

func FindTimeZoneFiles(zoneDir string) []string {
	dArr := make([]string, 0)
	dArr = append(dArr, "")
	arr := make([]string, 0)

	for i := 0; i < len(dArr); i++ {
		dir := dArr[i]
		files, _ := os.ReadDir(filepath.Join(zoneDir, dir))
		for _, f := range files {
			if f.Name() != strings.ToUpper(f.Name()[:1])+f.Name()[1:] {
				continue
			}
			if f.IsDir() {
				dArr = append(dArr, filepath.Join(dir, f.Name()))
			} else {
				arr = append(arr, filepath.Join(dir, f.Name()))
			}
		}
	}
	return arr
}
