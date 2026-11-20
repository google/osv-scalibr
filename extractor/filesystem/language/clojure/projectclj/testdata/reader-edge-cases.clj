;; Comments may contain [brackets] and "quotes".
(ns ^{:doc "not a project namespace"} leiningen.example)

(def docstring "a string with ) and ] and ; inside")

(defproject example/edge "1.0.0"
  :description "brackets ) ] } and \"escaped quotes\" in a string" ; trailing comment ]
  :regex #"\d+[)]"
  :chars [\( \) \] \space]
  :set #{:a :b}
  :inst #inst "2024-01-01T00:00:00.000-00:00"
  :fn #(str % "]")
  :cond #?(:clj 1 :cljs 2)
  :dependencies [#_[com.example/discarded "9.9.9"]
                 [org.clojure/clojure "1.11.1"] #_ [also/discarded "1.0"]
                 [com.example/after-discard "2.0"]]
  :jvm-opts ["-Xmx1g"])
