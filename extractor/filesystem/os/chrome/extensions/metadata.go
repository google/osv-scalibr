package extensions

type Metadata struct {
	Name                 string
	Description          string
	AuthorEmail          string
	HostPermissions      []string
	ManifestVersion      int
	MinimumChromeVersion string
	Permissions          []string
	UpdateURL            string
}
