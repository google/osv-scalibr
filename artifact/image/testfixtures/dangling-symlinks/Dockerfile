# Use Alpine as the builder since the final image is built on scratch
# which doesn't contain the `ln` command to generate symlinks.
#
# This dockerfile does not create the file, sample.txt in order to test for
# dangling symlinks.
FROM alpine:latest as builder

RUN mkdir dir1
RUN mkdir dir2
RUN mkdir dir2/dir3

RUN ln -s /dir1/sample.txt /dir1/absolute-symlink.txt
RUN ln -s ./sample.txt /dir1/relative-dot-symlink.txt
RUN ln -s sample.txt /dir1/relative-symlink.txt
RUN ln -s absolute-symlink.txt /dir1/chain-symlink.txt

RUN ln -s ../../dir1/sample.txt /dir2/dir3/relative-subfolder-symlink.txt
RUN ln -s /dir1/sample.txt /dir2/dir3/absolute-subfolder-symlink.txt
RUN ln -s /dir1/chain-symlink.txt /dir2/dir3/absolute-chain-symlink.txt

# - root
#   - dir1
#     - absolute-symlink.txt -> /dir1/sample.txt
#     - relative-dot-symlink.txt -> ./sample.txt
#     - relative-symlink.txt -> sample.txt
#     - chain-symlink.txt -> absolute-symlink.txt
#   - dir2
#     - dir3
#       - relative-subfolder-symlink.txt -> ../../dir1/sample.txt
#       - absolute-subfolder-symlink.txt -> /dir1/sample.txt
#       - absolute-chain-symlink.txt -> /dir1/chain-symlink.txt

FROM scratch

# Must copy over the entire directory to preserve the symlinks.
COPY --from=builder /dir1/ /dir1/
COPY --from=builder /dir2/ /dir2/
