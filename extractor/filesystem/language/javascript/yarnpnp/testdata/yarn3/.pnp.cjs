#!/usr/bin/env node
"use strict";

function $$SETUP_STATE(hydrateRuntimeState, basePath) {
  return hydrateRuntimeState(JSON.parse('{\
    "ignorePatternData": "(?:\\\\.yarn\\\\/sdks)",\
    "packageRegistryData": [\
      [null, [[null, {"packageLocation": "./", "linkType": "SOFT"}]]],\
      ["is-number", [["npm:7.0.0", {"packageLocation": ".yarn/cache/is-number/", "linkType": "HARD"}]]]\
    ]\
  }'), {basePath});
}
