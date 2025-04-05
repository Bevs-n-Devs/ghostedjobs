package tmpl

import (
	"fmt"
	"html/template"
	"os"

	"github.com/Bevs-n-Devs/ghostedjobs/logs"
)

func InitTemplates() {
	var err error
	Templates, err = template.ParseGlob("./tmpl/*.html")
	if err != nil {
		logs.Logs(logErr, fmt.Sprintf("Error parsing templates: %s", err.Error()))
		os.Exit(1)
	}
}
