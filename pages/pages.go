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
	pageTemplate, err = template.New("pages").Funcs(template.FuncMap{
		"emailHide": EmailHide,
	}).ParseFS(embeddedTemplates, "*.go.html")
	return
}

func RenderPageTemplate(wr io.Writer, name string, data any) {
	err := pageTemplate.ExecuteTemplate(wr, name+".go.html", data)
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
