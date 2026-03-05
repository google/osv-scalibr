# Use Alpine as the builder since the final image is built on scratch
# which doesn't contain the `ln` command to generate symlinks.
FROM alpine:latest as builder

RUN mkdir dir1
RUN mkdir dir2
RUN mkdir dir2/dir3

RUN echo "sample text" > dir1/sample.txt

RUN ln -s /dir1/sample.txt /dir1/symlink1.txt
RUN ln -s /dir1/symlink1.txt /dir1/symlink2.txt
RUN ln -s /dir1/symlink2.txt /dir1/symlink3.txt
RUN ln -s /dir1/symlink3.txt /dir1/symlink4.txt
RUN ln -s /dir1/symlink4.txt /dir1/symlink5.txt
RUN ln -s /dir1/symlink5.txt /dir1/symlink6.txt
RUN ln -s /dir1/symlink6.txt /dir1/symlink7.txt

# - root
#   - dir1
#     - sample.txt
#     - symlink1.txt -> /dir1/sample.txt
#     - symlink2.txt -> /dir1/symlink1.txt
#     - symlink3.txt -> /dir1/symlink2.txt
#     - symlink4.txt -> /dir1/symlink3.txt
#     - symlink5.txt -> /dir1/symlink4.txt
#     - symlink6.txt -> /dir1/symlink5.txt
#     - symlink7.txt -> /dir1/symlink6.txt

FROM scratch

# Must copy over the entire directory to preserve the symlinks.
COPY --from=builder /dir1/ /dir1/
