(def jackson-version "2.15.2")
(def ^:private ring-version "1.12.2")
(def slf4j-version "The version of slf4j, defined with a docstring." "2.0.13")

(defproject example/managed "1.0.0"
  :managed-dependencies [[org.slf4j/slf4j-api ~slf4j-version]
                         [ring/ring-core ~ring-version]]
  :dependencies [[org.slf4j/slf4j-api]
                 [ring/ring-core :exclusions [commons-io]]
                 [com.fasterxml.jackson.core/jackson-databind ~jackson-version]
                 [com.example/unresolved ~undefined-version]
                 [com.example/no-version-anywhere]])
