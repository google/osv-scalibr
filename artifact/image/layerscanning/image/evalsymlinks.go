package image

// EvalSymlinksFS returns the "real" path of a given path.
type EvalSymlinksFS interface {
	EvalSymlink(path string) (string, error)
}
