package autheliacfg

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var (
	standardDurationUnits = []string{"ns", "us", "µs", "μs", "ms", "s", "m", "h"}
	reDurationStandard    = regexp.MustCompile(`(?P<Duration>[1-9]\d*?)(?P<Unit>[^\d\s]+)`)
)

// Duration unit types.
const (
	DurationUnitDays   = "d"
	DurationUnitWeeks  = "w"
	DurationUnitMonths = "M"
	DurationUnitYears  = "y"
)

// Number of hours in particular measurements of time.
const (
	HoursInDay   = 24
	HoursInWeek  = HoursInDay * 7
	HoursInMonth = HoursInDay * 30
	HoursInYear  = HoursInDay * 365
)

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalText() ([]byte, error) {
	if d == 0 {
		return []byte("0s"), nil
	}
	ret, err := StandardizeDurationString(time.Duration(d).String())
	if err != nil {
		return nil, err
	}
	return []byte(ret), nil
}

// StandardizeDurationString converts units of time that stdlib is unaware of to hours.
//
// Source: https://github.com/authelia/authelia/blob/2d9137484eaf34e3913d0ec44e10d15127210225/internal/utils/time.go#L10-L47
func StandardizeDurationString(input string) (output string, err error) {
	if input == "" {
		return "0s", nil
	}

	matches := reDurationStandard.FindAllStringSubmatch(input, -1)

	if len(matches) == 0 {
		return "", fmt.Errorf("could not parse '%s' as a duration", input)
	}

	var d int

	for _, match := range matches {
		if d, err = strconv.Atoi(match[1]); err != nil {
			return "", fmt.Errorf("could not parse the numeric portion of '%s' in duration string '%s': %w", match[0],
				input, err)
		}

		unit := match[2]

		switch {
		case IsStringInSlice(unit, standardDurationUnits):
			output += fmt.Sprintf("%d%s", d, unit)
		case unit == DurationUnitDays:
			output += fmt.Sprintf("%dh", d*HoursInDay)
		case unit == DurationUnitWeeks:
			output += fmt.Sprintf("%dh", d*HoursInWeek)
		case unit == DurationUnitMonths:
			output += fmt.Sprintf("%dh", d*HoursInMonth)
		case unit == DurationUnitYears:
			output += fmt.Sprintf("%dh", d*HoursInYear)
		default:
			return "", fmt.Errorf("could not parse the units portion of '%s' in duration string '%s': the unit '%s' is not valid",
				match[0], input, unit)
		}
	}

	return output, nil
}

// IsStringInSlice checks if a single string is in a slice of strings.
func IsStringInSlice(needle string, haystack []string) (inSlice bool) {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}

	return false
}
