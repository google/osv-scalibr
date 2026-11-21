;; A typical project.clj.
(defproject example/basic "0.1.0-SNAPSHOT"
  :description "Basic project"
  :url "https://example.com"
  :license {:name "EPL-2.0" :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [cheshire "5.13.0"]
                 [ring/ring-core "1.12.2" :exclusions [commons-io]]
                 [com.fasterxml.jackson.core/jackson-databind "2.9.8"]]
  :plugins [[lein-ancient "1.0.0-RC3"]]
  :profiles {:dev {:dependencies [[org.clojure/test.check "1.1.1"]]}})
