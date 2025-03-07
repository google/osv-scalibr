package extensions

type Metadata struct {
	ID                   string `json:"id"`
	PublisherID          string `json:"publisherId"`
	PublisherDisplayName string `json:"publisherDisplayName"`
	TargetPlatform       string `json:"targetPlatform"`
	Updated              bool   `json:"updated"`
	IsPreReleaseVersion  bool   `json:"isPreReleaseVersion"`
	InstalledTimestamp   int64  `json:"installedTimestamp"`
}
