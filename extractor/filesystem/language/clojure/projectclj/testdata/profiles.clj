(defproject example/profiles "1.0.0"
  :dependencies [[org.clojure/clojure "1.12.0"]]
  :profiles {:dev [:base :system {:dependencies [[nrepl "1.3.0"]]}]
             :provided {:dependencies ^:replace [[org.clojure/clojure "1.12.0"]]}
             :uberjar {:aot :all}
             :1.10 {:dependencies [[org.clojure/clojure "1.10.3"]]}
             :test {:dependencies [[org.clojure/test.check "1.1.1" :scope "test"]]}})
