# Testdata Source

The `_gcfs.db` and `mock_content_store` files in this directory were manually
sourced from a live GKE node running image streaming (Riptide).

*   A standard `nginx` image was pulled on a node with image streaming enabled.
*   `/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db` was copied.

<!-- disableFinding(LINE_OVER_80) -->

*   `/var/lib/containerd/io.containerd.snapshotter.v1.gcfs/snapshotter/metadata.db`
    was copied.

<!-- enableFinding(LINE_OVER_80) -->

*   The corresponding raw image configuration and manifest blobs from the node's
    containerd content store
    (`/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/`) were
    also copied.

These files were then sanitized to remove sensitive data and unused records to
keep the test fixtures small and focused on the single mocked `nginx` container.
