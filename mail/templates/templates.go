package templates

import (
	"embed"
	"io"
	"log"
	"text/template"
)

var (
	//go:embed *
	embeddedTemplates embed.FS

	mailTemplate *template.Template
)

func LoadMailTemplates() (err error) {
	mailTemplate, err = template.New("mail").ParseFS(embeddedTemplates, "*.go.txt")
	return
}

func RenderMailTemplate(wr io.Writer, name string, data any) {
	err := mailTemplate.ExecuteTemplate(wr, name+".go.txt", data)
	if err != nil {
		log.Printf("Failed to render mail: %s: %s\n", name, err)
	}
}
