This directory stores Docker configs used to create the container tars for the testdata in scalibr/artifacts/image.


## Creating or updating testdata

1. Build the image.

  ```
  IMAGE_TAG="symlinks"
  DIRECTORY="symlinks"

  DOCKER_BUILDKIT=1 docker build -t $IMAGE_TAG third_party/scalibr/artifact/image/testfixtures/$DIRECTORY
  ```

1. Save the built image as a tar file in the `testdata` directory.

  ```
  IMAGE_TAG="symlinks"
  TAR_NAME="symlinks"

  docker save $IMAGE_TAG > third_party/scalibr/artifact/image/unpack/testdata/$TAR_NAME.tar
  ```
