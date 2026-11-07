/* Browser-only orchestration, compiled into every collector. */
async function completeAttestation(result, sendStep) {
  if (result["status"] === "passed" && typeof result["token"] === "string") return result["token"];
  if (result["status"] !== "step_up_pow" && result["status"] !== "step_up_visual") throw new Error("Invalid attestation response");
  var remainingMs = result["expiresAt"] - Date.now();
  if (remainingMs <= 0) throw new Error("Challenge expired. Please try again.");
  var controller = new AbortController();
  var modal = null;
  try {
    if (result["status"] === "step_up_visual") modal = openVisualChallenge(result["rendering"], remainingMs);
    var work = solvePoW({ "challenge": result["pow"]["challenge"], "difficulty": result["pow"]["difficulty"],
      "timeoutMs": remainingMs, "signal": controller["signal"] });
    var values = await Promise.all([work, modal ? modal["answer"] : Promise.resolve("")]);
    var verified = await sendStep({ "sessionId": result["sessionId"], "challengeId": result["challengeId"],
      "challengeToken": result["challengeToken"], "answer": values[1], "powSolution": values[0],
      "modalKinematics": modal ? modal["telemetry"]() : null });
    if (verified["status"] !== "passed" || typeof verified["token"] !== "string") throw new Error("Challenge verification failed");
    return verified["token"];
  } finally {
    controller["abort"]();
    if (modal) modal["destroy"]();
  }
}

function openVisualChallenge(instructions, ttl) {
  var previousFocus = document["activeElement"];
  var host = document["createElement"]("div");
  var shadow = host["attachShadow"]({ "mode": "closed" });
  var style = document["createElement"]("style");
  style["textContent"] = ":host{all:initial;position:fixed;inset:0;z-index:2147483647;font:15px system-ui;color:#e2e8f0}*{box-sizing:border-box}.backdrop{height:100%;display:grid;place-items:center;background:#020617b8;padding:20px}.card{width:min(390px,100%);padding:28px;background:#0f172a;border:1px solid #334155;border-radius:20px;box-shadow:0 24px 80px #0008}h2{font-size:22px;margin:0 0 10px}p{color:#94a3b8;line-height:1.5}canvas{width:100%;height:auto;border-radius:10px;margin:12px 0}label{display:block;margin:12px 0 8px}input{width:100%;padding:12px;background:#1e293b;color:white;border:1px solid #64748b;border-radius:8px;font:22px monospace;letter-spacing:5px}button{padding:12px;border:0;border-radius:8px;cursor:pointer;font:inherit}.actions{display:flex;gap:10px;margin-top:20px}.submit{flex:1;background:#38bdf8;color:#082f49}.cancel{background:#334155;color:white}:focus-visible{outline:3px solid #7dd3fc;outline-offset:3px}";
  shadow["appendChild"](style);
  var backdrop = document["createElement"]("div"); backdrop["className"] = "backdrop";
  var form = document["createElement"]("form"); form["className"] = "card";
  form["setAttribute"]("role", "dialog"); form["setAttribute"]("aria-modal", "true"); form["setAttribute"]("aria-label", "Security check");
  var heading = document["createElement"]("h2"); heading["textContent"] = "One quick security check";
  var help = document["createElement"]("p"); help["textContent"] = "Enter the six characters below. Uppercase and lowercase both work. This check expires in 60 seconds.";
  var canvas = document["createElement"]("canvas"); canvas["width"] = instructions["width"]; canvas["height"] = instructions["height"];
  canvas["setAttribute"]("aria-label", "Six distorted characters to transcribe");
  var label = document["createElement"]("label"); label["textContent"] = "Characters"; label["htmlFor"] = "challenge-answer";
  var input = document["createElement"]("input"); input["id"] = "challenge-answer"; input["maxLength"] = 6;
  input["required"] = true; input["pattern"] = "[A-Za-z2-9]{6}"; input["autocomplete"] = "off";
  var actions = document["createElement"]("div"); actions["className"] = "actions";
  var cancel = document["createElement"]("button"); cancel["type"] = "button"; cancel["className"] = "cancel"; cancel["textContent"] = "Cancel";
  var submit = document["createElement"]("button"); submit["type"] = "submit"; submit["className"] = "submit"; submit["textContent"] = "Verify";
  actions["append"](cancel, submit); form["append"](heading, help, canvas, label, input, actions);
  backdrop["appendChild"](form); shadow["appendChild"](backdrop); document["body"]["appendChild"](host);
  var frameTimer, expiryTimer, rejectAnswer, finished = false;
  var openedAt = performance["now"](), firstKey = null, lastKey = null, lastUp = null;
  var down = {}, dwells = [], intervals = [], trustedKeydowns = 0, untrustedCount = 0, pointerCount = 0;
  var screenSamples = 0, displacementSamples = 0, zeroScreen = 0, zeroMovement = 0, previousMove = null;
  var timestampSamples = 0, duplicateTimestamps = 0;
  var trustedPointerdowns = 0, trustedFocusChanges = 0, pointerBeforeTyping = false, focusBeforeTyping = false, focusIntent = -Infinity;
  function track(event) {
    if (finished) return;
    if (!event["isTrusted"]) { untrustedCount++; return; }
    var now = performance["now"](), type = event["type"], key = event["code"] || event["key"];
    if (type === "keydown" && event["key"] === "Tab") focusIntent = now;
    if (type === "pointerdown") {
      trustedPointerdowns++; focusIntent = now;
      if (event["target"] === input && firstKey === null) pointerBeforeTyping = true;
    }
    if (type === "focusin" && event["target"] === input && now - focusIntent < 1000) {
      trustedFocusChanges++; if (firstKey === null) focusBeforeTyping = true;
    }
    if (type === "pointermove" || type === "mousemove") {
      if (!document["fullscreenElement"] && [event["screenX"], event["screenY"], event["clientX"], event["clientY"]]["every"](Number["isFinite"])) {
        screenSamples++;
        if (event["screenX"] === event["clientX"] && event["screenY"] === event["clientY"]) zeroScreen++;
      }
      if (previousMove && (previousMove[0] !== event["clientX"] || previousMove[1] !== event["clientY"]) &&
          Number["isFinite"](event["movementX"]) && Number["isFinite"](event["movementY"])) {
        displacementSamples++;
        if (event["movementX"] === 0 && event["movementY"] === 0) zeroMovement++;
      }
      if (previousMove && Number["isFinite"](event["timeStamp"]) && Number["isFinite"](previousMove[2])) {
        timestampSamples++; if (event["timeStamp"] <= previousMove[2]) duplicateTimestamps++;
      }
      previousMove = [event["clientX"], event["clientY"], event["timeStamp"]];
    }
    if (type === "keydown" && event["target"] === input && !event["repeat"] && event["key"]["length"] === 1) {
      if (firstKey === null) firstKey = now;
      if (lastKey !== null) intervals["push"](now - lastKey);
      lastKey = now; trustedKeydowns++; down[key] = now;
    } else if (type === "keyup" && Object["prototype"]["hasOwnProperty"]["call"](down, key)) {
      dwells["push"](now - down[key]); delete down[key]; lastUp = now;
    } else if (type === "pointermove" || type === "mousemove" || type === "pointerdown") pointerCount++;
  }
  var eventTypes = ["keydown", "keyup", typeof window["PointerEvent"] === "function" ? "pointermove" : "mousemove", "pointerdown", "focusin"];
  eventTypes["forEach"](function(type) { shadow["addEventListener"](type, track, true); });
  function variance(values) {
    if (values["length"] < 2) return 0;
    var mean = values["reduce"](function(a, b) { return a + b; }, 0) / values["length"];
    return values["reduce"](function(a, b) { return a + (b - mean) * (b - mean); }, 0) / values["length"];
  }
  function telemetry() {
    return { "untrustedCount": untrustedCount, "trustedKeydowns": trustedKeydowns, "pointerCount": pointerCount,
      "trustedPointerdowns": trustedPointerdowns, "trustedFocusChanges": trustedFocusChanges,
      "pointerBeforeTyping": pointerBeforeTyping, "focusBeforeTyping": focusBeforeTyping,
      "screenSamples": screenSamples, "displacementSamples": displacementSamples,
      "zeroScreenDeltaRatio": screenSamples ? zeroScreen / screenSamples : 0,
      "zeroMovementRatio": displacementSamples ? zeroMovement / displacementSamples : 0,
      "duplicateTimestampRatio": timestampSamples ? duplicateTimestamps / timestampSamples : 0,
      "dwellCount": dwells["length"], "ttfkMs": firstKey === null ? 0 : firstKey - openedAt,
      "totalTypingMs": firstKey === null || lastUp === null ? 0 : lastUp - firstKey,
      "dwellVariance": variance(dwells), "intervalVariance": variance(intervals) };
  }
  var ctx = canvas["getContext"]("2d");
  var picture = new Image();
  picture["onload"] = function() { if (ctx) ctx["drawImage"](picture, 0, 0); };
  picture["src"] = instructions["image"];
  function paint() {}
  function destroy() {
    eventTypes["forEach"](function(type) { shadow["removeEventListener"](type, track, true); });
    clearInterval(frameTimer); clearTimeout(expiryTimer); host["remove"]();
    if (!finished && rejectAnswer) { finished = true; rejectAnswer(new Error("Challenge closed")); }
    if (previousFocus && previousFocus["focus"]) previousFocus["focus"]();
  }
  var answer = new Promise(function(resolve, reject) {
    rejectAnswer = reject;
    function fail(message) { if (!finished) { finished = true; reject(new Error(message)); } }
    cancel["addEventListener"]("click", function() { fail("Challenge cancelled"); });
    form["addEventListener"]("keydown", function(event) {
      if (event["key"] === "Escape") { event["preventDefault"](); fail("Challenge cancelled"); }
      if (event["key"] === "Tab") {
        var first = input, last = submit;
        if (event["shiftKey"] && shadow["activeElement"] === first) { event["preventDefault"](); last["focus"](); }
        else if (!event["shiftKey"] && shadow["activeElement"] === last) { event["preventDefault"](); first["focus"](); }
      }
    });
    form["addEventListener"]("submit", function(event) {
      event["preventDefault"]();
      if (!finished && form["checkValidity"]()) { finished = true; submit["disabled"] = true; submit["textContent"] = "Checking..."; resolve(input["value"]); }
    });
    expiryTimer = setTimeout(function() { fail("Challenge expired. Please try again."); }, ttl);
  });
  try {
    paint();

    input["focus"]();
  } catch (error) { answer["catch"](function() {}); destroy(); throw error; }
  return { "answer": answer, "destroy": destroy, "telemetry": telemetry };
}
