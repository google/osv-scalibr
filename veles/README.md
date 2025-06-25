# Veles: secret scanning

> Veles – Slavic god, a permanent guardian on the border of the worlds, a spiritual mentor, _he knows all the secrets of the universe_.

Veles is a standalone library for secret scanning that ships as part of Scalibr.
It can detect _and (where possible) validate_ credentials and other things
colloquially referred to as "secrets".

The API is designed to make it easy to add new [Detector](./detect.go)s and
corresponding [Validator](./validate.go)s. The [DetectionEngine](./detect.go#52)
is deliberately kept simple for now. In the future, if Veles supports hundreds
or thousands of credential types, the engine might require optimization (e.g.
using the Aho-Corasick algorithm).

It can be used via Scalibr via the corresponding extractor and enricher. Some
parts of that integration are still under development.
