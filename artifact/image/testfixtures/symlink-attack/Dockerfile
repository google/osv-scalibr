# Use Alpine as the builder since the final image is built on scratch
# which doesn't contain the `ln` command to generate symlinks.
FROM alpine:latest as builder

RUN mkdir dir1

RUN ln -s ../../secret.txt /dir1/attack-symlink.txt
RUN ln -s /../secret.txt /dir1/attack-symlink-absolute.txt

# - root
#   - dir1
#     - attack-symlink.txt -> ../../secret.txt
#     - attack-symlink-absolute.txt -> /../secret.txt

FROM scratch

# Must copy over the entire directory to preserve the symlinks.
COPY --from=builder /dir1/ /dir1/
