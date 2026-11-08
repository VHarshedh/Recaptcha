"use strict";
// Never persist this identity: a new process must reject tokens whose local
// replay history was lost at restart. Shared-store verification ignores it.
module.exports = require("node:crypto").randomBytes(32).toString("hex");
