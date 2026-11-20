;; Profiles that include other profiles by name, as in the Luminus template.
(defproject example/profile-references "1.0.0"
  :dependencies [[org.clojure/clojure "1.12.0"]]
  :profiles {:dev              [:project/dev :profiles/dev {:dependencies [[nrepl "1.3.0"]]}]
             :test             [:dev :shared :project/test]
             :provided         :project/provided
             :uberjar          [:project/release]
             :project/dev      [:shared {:dependencies [[abc/xyz "1.0.0"]]}]
             :project/test     {:dependencies [[org.example/test-only "2.0"]]}
             :project/provided {:dependencies [[javax.servlet/servlet-api "2.5"]]}
             :project/release  {:dependencies [[org.example/release-only "9.9"]]}
             :shared           [:project/dev {:dependencies [[org.example/shared "3.0"]]}]
             :1.11             {:dependencies [[org.example/example "1.2.3"]]}})
