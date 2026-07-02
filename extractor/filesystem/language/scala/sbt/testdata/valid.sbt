name := "my-project"

version := "0.1.0"

scalaVersion := "3.3.1"

libraryDependencies += "org.scala-native" %%% "scala-native-java-logging" % "1.0.0"

libraryDependencies += "com.twitter" %% "finagle-core" % "24.2.0"

libraryDependencies += "org.scala-lang" % "toolkit_3" % "0.2.0"

libraryDependencies += "org.apache.pekko" %% "pekko-testkit" % "1.4.0" % Test

libraryDependencies ++= Seq(
  "org.dep1" %% "toolkit" % "1.2.3",
  "org.dep2" %% "toolkit" % "4.5.6"
)
