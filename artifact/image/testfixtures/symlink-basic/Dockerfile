# Use Alpine as the builder since the final image is built on scratch
# which doesn't contain the `ln` command to generate symlinks.
FROM alpine:latest as builder

RUN mkdir dir1

RUN echo "sample text" > dir1/sample.txt

RUN ln -s /dir1/sample.txt /dir1/absolute-symlink.txt
RUN ln -s ./sample.txt /dir1/relative-dot-symlink.txt
RUN ln -s sample.txt /dir1/relative-symlink.txt
RUN ln -s absolute-symlink.txt /dir1/chain-symlink.txt

# - root
#   - dir1
#     - sample.txt
#     - absolute-symlink.txt -> /dir1/sample.txt
#     - relative-dot-symlink.txt -> ./sample.txt
#     - relative-symlink.txt -> sample.txt

FROM scratch

# Must copy over the entire directory to preserve the symlinks.
COPY --from=builder /dir1/ /dir1/
