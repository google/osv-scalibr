package extensions

type Metadata struct {
	AuthorEmail          string   `json:"author_email"`
	Description          string   `json:"description"`
	HostPermissions      []string `json:"host_permissions"`
	ManifestVersion      int      `json:"manifest_version"`
	MinimumChromeVersion string   `json:"minimum_chrome_version"`
	Name                 string   `json:"name"`
	Permissions          []string `json:"permissions"`
	UpdateURL            string   `json:"update_url"`
	Version              string   `json:"version"`
}
