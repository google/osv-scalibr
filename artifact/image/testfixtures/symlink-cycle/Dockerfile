# Use Alpine as the builder since the final image is built on scratch
# which doesn't contain the `ln` command to generate symlinks.
FROM alpine:latest as builder

RUN mkdir dir1

RUN ln -s /dir1/sample.txt /dir1/absolute-symlink.txt
RUN ln -s absolute-symlink.txt /dir1/chain-symlink.txt
RUN ln -s /dir1/chain-symlink.txt /dir1/sample.txt

# - root
#   - dir1
#     - /dir1/sample.txt -> /dir1/absolute-symlink.txt
#     - absolute-symlink.txt -> /dir1/chain-symlink.txt
#     - /dir1/chain-symlink.txt -> /dir1/sample.txt

FROM scratch

# Must copy over the entire directory to preserve the symlinks.
COPY --from=builder /dir1/ /dir1/
