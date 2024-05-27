Remove-Item -Recurse -Force binary/proto/*_go_proto
protoc -I=binary --go_out=binary/proto binary/proto/*.proto
Move-Item binary/proto/github.com/google/scalibr/binary/proto/* binary/proto/
Remove-Item -Recurse -Force binary/proto/github.com
