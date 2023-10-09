package pages

import (
	"embed"
	_ "embed"
	"errors"
	"github.com/1f349/overlapfs"
	"html/template"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
)

var (
	//go:embed *.go.html
	wwwPages     embed.FS
	wwwTemplates *template.Template
	loadOnce     sync.Once
)

func LoadPages(wd string) (err error) {
	loadOnce.Do(func() {
		var o fs.FS = wwwPages
		if wd != "" {
			wwwDir := filepath.Join(wd, "www")
			err = os.Mkdir(wwwDir, os.ModePerm)
			if err != nil && !errors.Is(err, os.ErrExist) {
				return
			}
			wdFs := os.DirFS(wwwDir)
			o = overlapfs.OverlapFS{A: wwwPages, B: wdFs}
		}
		wwwTemplates, err = template.New("pages").Funcs(template.FuncMap{
			"emailHide": EmailHide,
		}).ParseFS(o, "*.go.html")
	})
	return err
}

func RenderPageTemplate(wr io.Writer, name string, data any) {
	err := wwwTemplates.ExecuteTemplate(wr, name+".go.html", data)
	if err != nil {
		log.Printf("Failed to render page: %s: %s\n", name, err)
	}
}

func EmailHide(a string) string {
	b := []byte(a)
	for i := range b {
		if b[i] != '@' && b[i] != '.' {
			b[i] = 'x'
		}
	}
	return string(b)
}
