/**
 * kinematics.js — Mouse / Touch / Keyboard Tracker
 *
 * Records input events and computes entropy, straight-line ratio,
 * jitter, and velocity statistics for human-likeness scoring.
 */

function createKinematics() {
  var moveEvents = [];
  var keyCount = 0;
  var scrollCount = 0;
  var clickCount = 0;
  var listening = false;

  function onMove(evt) {
    moveEvents["push"]({
      "x": evt["clientX"],
      "y": evt["clientY"],
      "t": performance["now"]()
    });
  }

  function onKey() { keyCount++; }
  function onScroll() { scrollCount++; }
  function onClick() { clickCount++; }

  function start() {
    if (listening) return;
    listening = true;
    document["addEventListener"]("mousemove", onMove, { "passive": true, "capture": true });
    document["addEventListener"]("keydown", onKey, { "passive": true });
    document["addEventListener"]("scroll", onScroll, { "passive": true });
    document["addEventListener"]("click", onClick, { "passive": true });
  }

  function stop() {
    if (!listening) return;
    listening = false;
    document["removeEventListener"]("mousemove", onMove, true);
    document["removeEventListener"]("keydown", onKey);
    document["removeEventListener"]("scroll", onScroll);
    document["removeEventListener"]("click", onClick);
  }

  function computeStats() {
    stop();

    var out = {};
    out["humanLike"] = false;
    out["entropy"] = 0;
    out["straightLineRatio"] = 0;
    out["eventCount"] = moveEvents["length"];
    out["keyEvents"] = keyCount;
    out["scrollEvents"] = scrollCount;
    out["clickEvents"] = clickCount;
    out["jitter"] = 0;
    out["avgVelocity"] = 0;

    if (moveEvents["length"] < 5) return out;

    var velocities = [];
    var angles = [];
    var totalDist = 0;
    var idx;

    for (idx = 1; idx < moveEvents["length"]; idx++) {
      var dx = moveEvents[idx]["x"] - moveEvents[idx - 1]["x"];
      var dy = moveEvents[idx]["y"] - moveEvents[idx - 1]["y"];
      var dt = moveEvents[idx]["t"] - moveEvents[idx - 1]["t"];
      var segDist = Math["sqrt"](dx * dx + dy * dy);
      totalDist += segDist;
      if (dt > 0) velocities["push"](segDist / dt);
      angles["push"](Math["atan2"](dy, dx));
    }

    // Straight-line ratio: euclidean(start,end) / total path
    if (moveEvents["length"] >= 2 && totalDist > 0) {
      var dxTotal = moveEvents[moveEvents["length"] - 1]["x"] - moveEvents[0]["x"];
      var dyTotal = moveEvents[moveEvents["length"] - 1]["y"] - moveEvents[0]["y"];
      var directDist = Math["sqrt"](dxTotal * dxTotal + dyTotal * dyTotal);
      out["straightLineRatio"] = directDist / totalDist;
    }

    // Velocity entropy (normalized std-dev / mean)
    if (velocities["length"] > 1) {
      var velSum = 0;
      var vi;
      for (vi = 0; vi < velocities["length"]; vi++) velSum += velocities[vi];
      var velMean = velSum / velocities["length"];
      var varSum = 0;
      for (vi = 0; vi < velocities["length"]; vi++) {
        var vdiff = velocities[vi] - velMean;
        varSum += vdiff * vdiff;
      }
      var velStd = Math["sqrt"](varSum / velocities["length"]);
      out["entropy"] = Math["min"](1, velStd / (velMean + 0.001));
      out["avgVelocity"] = velMean;
    }

    // Angular jitter: mean absolute angular change
    if (angles["length"] > 1) {
      var jitterSum = 0;
      var ai;
      for (ai = 1; ai < angles["length"]; ai++) {
        jitterSum += Math["abs"](angles[ai] - angles[ai - 1]);
      }
      out["jitter"] = jitterSum / (angles["length"] - 1);
    }

    // Human-likeness heuristic
    out["humanLike"] = (
      out["eventCount"] > 10 &&
      out["entropy"] > 0.1 &&
      out["straightLineRatio"] < 0.95 &&
      out["jitter"] > 0.05
    );

    return out;
  }

  var kinObj = {};
  kinObj["start"] = start;
  kinObj["stop"] = stop;
  kinObj["snapshot"] = computeStats;
  return kinObj;
}
