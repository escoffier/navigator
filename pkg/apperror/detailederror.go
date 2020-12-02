package apperror

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type Suberror struct {
	Location string
	Message  string
}

func (suberror Suberror) String() string {
	message := suberror.Message
	if message == "" {
		message = "<empty>"
	}
	return fmt.Sprintf("%s: %s", suberror.Location, message)
}

type detailedError struct {
	err error

	English  string
	Zhongwen string

	HTTPCode  int
	Suberrors []Suberror

	File string
	Line int
}

func (de detailedError) Error() string {
	msg := fmt.Sprintf("DetailedError<En: %s, Zh: %s, Code: %d, Location: %s:%d, Suberrors: ", de.English, de.Zhongwen, de.HTTPCode, de.File, de.Line)
	if len(de.Suberrors) == 0 {
		msg += "<none>"
	} else {
		msg += "["
		suberrStrings := []string{}
		for _, suberr := range de.Suberrors {
			suberrStrings = append(suberrStrings, suberr.String())
		}
		msg += strings.Join(suberrStrings, ", ")
		msg += "]"
	}
	msg += ">: "
	return msg + de.err.Error()
}

func (de detailedError) Unwrap() error {
	return de.err
}

// As method is implemented to satisfy interface of errors.As:
// var det detailedError
// if errors.As(err, &det) {
// 	fmt.Println("detailedError:", det.http, det.Zhongwen)
// }
// var anerror AnError
// if errors.As(err, &anerror) {
// 	fmt.Println(anerror)
// }
func (de detailedError) As(target interface{}) bool {
	tgt, ok := target.(*detailedError)
	if ok {
		*tgt = de
		return true
	}
	return false
}

func (de detailedError) LocalizedError(ctx context.Context) string {
	languageKey := lang.Language(ctx)
	if languageKey == lang.LanguageZH {
		return de.Zhongwen
	} else if languageKey == lang.LanguageEN {
		return de.English
	} else {
		logging.GetLogger().Warn().
			Str("languageKey", string(languageKey)).
			Msg("LocalizedError: Couldn't recognize language, defaulting to English")
		return de.English
	}
}
