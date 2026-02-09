// https://docs.deno.com/runtime/fundamentals/modules/

// HTTPS imports
// "https://esm.sh/PKG[@SEMVER][/PATH]";
import confetti from "https://esm.sh/canvas-confetti@1.6.0";
import confettiLatest from "https://esm.sh/canvas-confetti";

// "https://deno.land/x/IDENTIFIER@VERSION/FILE_PATH";
import openai from "https://deno.land/x/openai@v4.69.0/mod.ts";
import openaiLatest from "https://deno.land/x/openai/mod.ts";

// "https://unpkg.com/:package@:version/:file";
import {debounce} from "https://unpkg.com/lodash-es@4.17.21/lodash.js";

const dynamicImport = await import(
    "https://unpkg.com/lodash-es@4.17.22/lodash.js"
    );

// import {camelCase} from "jsr:@luca/cases@1.0.0";
// import {say} from "npm:cowsay@1.6.0";

console.log(
    confetti,
    confettiLatest,
    openai,
    openaiLatest,
    debounce,
    dynamicImport,
);
