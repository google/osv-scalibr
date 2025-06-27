package image

type EvalSymlinksFS interface {
	// EvalSymlink returns the "real" path of a given path.
	// This only works for paths where an actual file (symlink or otherwise) actually exists at that location.
	EvalSymlink(path string) (string, error)
}
