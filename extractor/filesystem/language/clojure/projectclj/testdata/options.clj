(defproject example/options "1.0.0"
  :dependencies [[org.lwjgl/lwjgl "3.3.3" :classifier "natives-linux"]
                 [com.example/bundle "1.0" :extension "pom"]
                 [midje "1.10.9" :scope "test"]
                 [javax.servlet/servlet-api "2.5" :scope "provided"]
                 [com.example/explicit-compile "2.0" :scope "compile"]
                 ["com.example/string-coord" "3.0"]])
