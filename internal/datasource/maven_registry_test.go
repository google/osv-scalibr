package datasource_test

import (
	"context"
	"reflect"
	"testing"

	"deps.dev/util/maven"
	"github.com/google/osv-scalibr/internal/datasource"
	"github.com/google/osv-scalibr/internal/resolution/clienttest"
)

func TestGetProject(t *testing.T) {
	t.Parallel()

	srv := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: srv.URL, ReleasesEnabled: true})
	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))

	got, err := client.GetProject(context.Background(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "1.0.0", err)
	}
	want := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "1.0.0",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "1.0.0", got, want)
	}
}

func TestGetProjectSnapshot(t *testing.T) {
	t.Parallel()

	srv := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: srv.URL, SnapshotsEnabled: true})
	srv.SetResponse(t, "org/example/x.y.z/3.3.1-SNAPSHOT/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	  <snapshot>
	    <timestamp>20230302.052731</timestamp>
	    <buildNumber>9</buildNumber>
	  </snapshot>
	  <lastUpdated>20230302052731</lastUpdated>
	  <snapshotVersions>
	    <snapshotVersion>
	      <extension>jar</extension>
	      <value>3.3.1-20230302.052731-9</value>
	      <updated>20230302052731</updated>
	    </snapshotVersion>
	    <snapshotVersion>
	      <extension>pom</extension>
	      <value>3.3.1-20230302.052731-9</value>
	      <updated>20230302052731</updated>
	    </snapshotVersion>
	  </snapshotVersions>
	  </versioning>
	</metadata>
	`))
	srv.SetResponse(t, "org/example/x.y.z/3.3.1-SNAPSHOT/x.y.z-3.3.1-20230302.052731-9.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>3.3.1-SNAPSHOT</version>
	</project>
	`))

	got, err := client.GetProject(context.Background(), "org.example", "x.y.z", "3.3.1-SNAPSHOT")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "3.3.1-SNAPSHOT", err)
	}
	want := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "3.3.1-SNAPSHOT",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "3.3.1-SNAPSHOT", got, want)
	}
}

func TestMultipleRegistry(t *testing.T) {
	t.Parallel()

	dft := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: dft.URL, ReleasesEnabled: true})
	dft.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>3.0.0</latest>
	    <release>3.0.0</release>
	    <versions>
	      <version>2.0.0</version>
		  <version>3.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))
	dft.SetResponse(t, "org/example/x.y.z/2.0.0/x.y.z-2.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>2.0.0</version>
	</project>
	`))
	dft.SetResponse(t, "org/example/x.y.z/3.0.0/x.y.z-3.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>3.0.0</version>
	</project>
	`))

	srv := clienttest.NewMockHTTPServer(t)
	if err := client.AddRegistry(datasource.MavenRegistry{URL: srv.URL, ReleasesEnabled: true}); err != nil {
		t.Fatalf("failed to add registry %s: %v", srv.URL, err)
	}
	srv.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>2.0.0</latest>
	    <release>2.0.0</release>
	    <versions>
	      <version>1.0.0</version>
		  <version>2.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))
	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))
	srv.SetResponse(t, "org/example/x.y.z/2.0.0/x.y.z-2.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>2.0.0</version>
	</project>
	`))

	gotProj, err := client.GetProject(context.Background(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "1.0.0", err)
	}
	wantProj := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "1.0.0",
		},
	}
	if !reflect.DeepEqual(gotProj, wantProj) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "1.0.0", gotProj, wantProj)
	}

	gotVersions, err := client.GetVersions(context.Background(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions := []maven.String{"1.0.0", "2.0.0", "3.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}
}
