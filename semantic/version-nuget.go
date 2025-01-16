package semantic

import "strings"

type nuGetVersion struct {
	semverLikeVersion
}

func (v nuGetVersion) compare(w nuGetVersion) int {
	if diff := v.Components.Cmp(w.Components); diff != 0 {
		return diff
	}

	return compareBuildComponents(strings.ToLower(v.Build), strings.ToLower(w.Build))
}

func (v nuGetVersion) CompareStr(str string) (int, error) {
	w, err := parseNuGetVersion(str)

	if err != nil {
		return 0, err
	}

	return v.compare(w), nil
}

func parseNuGetVersion(str string) (nuGetVersion, error) {
	return nuGetVersion{parseSemverLikeVersion(str, 4)}, nil
}
