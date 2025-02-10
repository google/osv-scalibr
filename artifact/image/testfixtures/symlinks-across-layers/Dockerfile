# Use Alpine as the builder since the final image is built on scratch
# which doesn't contain the `ln` command to generate symlinks.
FROM alpine:latest as builder

RUN mkdir dir1
RUN mkdir dir2
RUN mkdir


RUN echo "sample text" > dir1/sample.txt
RUN ln -s /dir1/sample.txt /dir2/absolute-symlink.txt
RUN ln -s /dir2/absolute-symlink.txt /dir3/chain-symlink.txt


# - root
#   - dir1
#     - sample.txt
#   - dir2
#     - absolute-symlink.txt -> /dir1/sample.txt
#   - dir3
#     - chain-symlink.txt -> /dir2absolute-symlink.txt
FROM scratch

# Must copy over the entire directory to preserve the symlinks.
COPY --from=builder /dir3/ /dir3/
COPY --from=builder /dir2/ /dir2/
COPY --from=builder /dir1/ /dir1/
