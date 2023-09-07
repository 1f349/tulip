package lists

import (
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
	"sync"
)

var (
	localeOnce  sync.Once
	localeNames []struct{ Value, Label string }
)

func ListLocale() []struct{ Value, Label string } {
	localeOnce.Do(func() {
		localeNames = make([]struct{ Value, Label string }, len(localeList))
		for i := range localeList {
			localeNames[i] = struct{ Value, Label string }{Value: localeList[i].String(), Label: display.Self.Name(localeList[i])}
		}
	})
	return localeNames
}

var localeList = []language.Tag{
	language.Afrikaans,
	language.Amharic,
	language.Arabic,
	language.ModernStandardArabic,
	language.Azerbaijani,
	language.Bulgarian,
	language.Bengali,
	language.Catalan,
	language.Czech,
	language.Danish,
	language.German,
	language.Greek,
	language.English,
	language.AmericanEnglish,
	language.BritishEnglish,
	language.Spanish,
	language.EuropeanSpanish,
	language.LatinAmericanSpanish,
	language.Estonian,
	language.Persian,
	language.Finnish,
	language.Filipino,
	language.French,
	language.CanadianFrench,
	language.Gujarati,
	language.Hebrew,
	language.Hindi,
	language.Croatian,
	language.Hungarian,
	language.Armenian,
	language.Indonesian,
	language.Icelandic,
	language.Italian,
	language.Japanese,
	language.Georgian,
	language.Kazakh,
	language.Khmer,
	language.Kannada,
	language.Korean,
	language.Kirghiz,
	language.Lao,
	language.Lithuanian,
	language.Latvian,
	language.Macedonian,
	language.Malayalam,
	language.Mongolian,
	language.Marathi,
	language.Malay,
	language.Burmese,
	language.Nepali,
	language.Dutch,
	language.Norwegian,
	language.Punjabi,
	language.Polish,
	language.Portuguese,
	language.BrazilianPortuguese,
	language.EuropeanPortuguese,
	language.Romanian,
	language.Russian,
	language.Sinhala,
	language.Slovak,
	language.Slovenian,
	language.Albanian,
	language.Serbian,
	language.SerbianLatin,
	language.Swedish,
	language.Swahili,
	language.Tamil,
	language.Telugu,
	language.Thai,
	language.Turkish,
	language.Ukrainian,
	language.Urdu,
	language.Uzbek,
	language.Vietnamese,
	language.Chinese,
	language.SimplifiedChinese,
	language.TraditionalChinese,
	language.Zulu,
}
