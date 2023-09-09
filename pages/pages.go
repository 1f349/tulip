package pages

import (
	"embed"
	_ "embed"
	"html/template"
	"io"
	"log"
)

var (
	//go:embed *
	embeddedTemplates embed.FS

	pageTemplate *template.Template
)

func LoadPageTemplates() (err error) {
	pageTemplate, err = template.New("pages").ParseFS(embeddedTemplates, "*.go.html")
	return
}

func RenderPageTemplate(wr io.Writer, name string, data any) {
	err := pageTemplate.ExecuteTemplate(wr, name+".go.html", data)
	if err != nil {
		log.Printf("Failed to render page: %s: %s\n", name, err)
	}
}
