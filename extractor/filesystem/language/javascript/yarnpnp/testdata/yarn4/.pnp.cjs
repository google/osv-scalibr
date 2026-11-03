#!/usr/bin/env node
"use strict";

const RAW_RUNTIME_STATE =
'{\
  "packageRegistryData": [\
    [null, [[null, {"packageLocation": "./", "linkType": "SOFT"}]]],\
    ["left-pad", [["npm:1.3.0", {"packageLocation": ".yarn/cache/left-pad/", "linkType": "HARD"}]]]\
  ]\
}';

function $$SETUP_STATE(hydrateRuntimeState, basePath) {
  return hydrateRuntimeState(JSON.parse(RAW_RUNTIME_STATE), {basePath});
}
