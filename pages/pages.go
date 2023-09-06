package pages

import (
	"embed"
	_ "embed"
	"html/template"
	"io"
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

func RenderPageTemplate(wr io.Writer, name string, data any) error {
	return pageTemplate.ExecuteTemplate(wr, name+".go.html", data)
}
