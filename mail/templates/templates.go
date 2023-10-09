package templates

import (
	"embed"
	"errors"
	"github.com/1f349/overlapfs"
	htmlTemplate "html/template"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	textTemplate "text/template"
)

var (
	//go:embed *.go.html *.go.txt
	embeddedTemplates embed.FS
	mailHtmlTemplates *htmlTemplate.Template
	mailTextTemplates *textTemplate.Template
	loadOnce          sync.Once
)

func LoadMailTemplates(wd string) (err error) {
	loadOnce.Do(func() {
		var o fs.FS = embeddedTemplates
		if wd != "" {
			mailDir := filepath.Join(wd, "mail-templates")
			err = os.Mkdir(mailDir, os.ModePerm)
			if err != nil && !errors.Is(err, os.ErrExist) {
				return
			}
			wdFs := os.DirFS(mailDir)
			o = overlapfs.OverlapFS{A: embeddedTemplates, B: wdFs}
		}
		mailHtmlTemplates, err = htmlTemplate.New("mail").ParseFS(o, "*.go.html")
		if err != nil {
			return
		}
		mailTextTemplates, err = textTemplate.New("mail").ParseFS(o, "*.go.txt")
	})
	return
}

func RenderMailTemplate(wrHtml, wrTxt io.Writer, name string, data any) {
	err := mailHtmlTemplates.ExecuteTemplate(wrHtml, name+".go.html", data)
	if err != nil {
		log.Printf("Failed to render mail html: %s: %s\n", name, err)
	}
	err = mailTextTemplates.ExecuteTemplate(wrTxt, name+".go.txt", data)
	if err != nil {
		log.Printf("Failed to render mail text: %s: %s\n", name, err)
	}
}
