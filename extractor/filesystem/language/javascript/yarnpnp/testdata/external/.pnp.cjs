#!/usr/bin/env node
"use strict";

function $$SETUP_STATE(hydrateRuntimeState, basePath) {
  const fs = require("fs");
  return hydrateRuntimeState(JSON.parse(fs.readFileSync(".pnp.data.json", "utf8")), {basePath});
}
