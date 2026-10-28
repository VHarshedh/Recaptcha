"use strict";
const crypto = require("node:crypto");

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
// Original 5x7 outline templates. Only transformed path commands leave the server.
const FONT = {
  A:"01110/10001/10001/11111/10001/10001/10001", B:"11110/10001/10001/11110/10001/10001/11110",
  C:"01111/10000/10000/10000/10000/10000/01111", D:"11110/10001/10001/10001/10001/10001/11110",
  E:"11111/10000/10000/11110/10000/10000/11111", F:"11111/10000/10000/11110/10000/10000/10000",
  G:"01111/10000/10000/10111/10001/10001/01111", H:"10001/10001/10001/11111/10001/10001/10001",
  J:"00111/00010/00010/00010/10010/10010/01100", K:"10001/10010/10100/11000/10100/10010/10001",
  L:"10000/10000/10000/10000/10000/10000/11111", M:"10001/11011/10101/10101/10001/10001/10001",
  N:"10001/11001/10101/10011/10001/10001/10001", P:"11110/10001/10001/11110/10000/10000/10000",
  Q:"01110/10001/10001/10001/10101/10010/01101", R:"11110/10001/10001/11110/10100/10010/10001",
  S:"01111/10000/10000/01110/00001/00001/11110", T:"11111/00100/00100/00100/00100/00100/00100",
  U:"10001/10001/10001/10001/10001/10001/01110", V:"10001/10001/10001/10001/10001/01010/00100",
  W:"10001/10001/10001/10101/10101/11011/10001", X:"10001/10001/01010/00100/01010/10001/10001",
  Y:"10001/10001/01010/00100/00100/00100/00100", Z:"11111/00001/00010/00100/01000/10000/11111",
  2:"01110/10001/00001/00010/00100/01000/11111", 3:"11110/00001/00001/01110/00001/00001/11110",
  4:"00010/00110/01010/10010/11111/00010/00010", 5:"11111/10000/10000/11110/00001/00001/11110",
  6:"01110/10000/10000/11110/10001/10001/01110", 7:"11111/00001/00010/00100/01000/01000/01000",
  8:"01110/10001/10001/01110/10001/10001/01110", 9:"01110/10001/10001/01111/00001/00001/01110",
};
const random = (lo, hi) => lo + crypto.randomInt(1_000_000) / 1_000_000 * (hi - lo);
function answerHash(secret, answer, challengeId) {
  return crypto.createHmac("sha256", secret).update(answer.toLowerCase() + challengeId).digest();
}

function renderAnswer(answer) {
  const palette = ["#334155", "#475569", "#536479"], paths = [];
  const layerOffsets = Array.from({ length: 3 }, (_, layer) => [random(-80, 80) + layer * 55, random(-55, 55)]);
  const phase = random(0, Math.PI * 2);
  function transform(cx, cy) {
    const angle = random(-28, 28) * Math.PI / 180, shear = random(-0.14, 0.14);
    const scale = random(0.9, 1.08), wave = random(0.8, 2.3);
    return (x, y) => {
      x = (x - 12.5) * scale + shear * y + wave * Math.sin(y / 8 + phase);
      y -= 17.5;
      return [cx + x * Math.cos(angle) - y * Math.sin(angle), cy + x * Math.sin(angle) + y * Math.cos(angle)];
    };
  }
  function blob(point, x, y, layer, phaseOffset = 0) {
    const w = random(2.3, 2.9), h = random(4.5, 5.5), bend = random(-0.5, 0.5);
    const p = (a, b) => {
      const v = point(a, b);
      return (v[0] - layerOffsets[layer][0] + phaseOffset).toFixed(2) + " " +
        (v[1] - layerOffsets[layer][1] - phaseOffset).toFixed(2);
    };
    paths.push({ d: "M" + p(x,y) + "C" + p(x+w,y+bend) + " " + p(x+w,y+h/2) + " " + p(x+w,y+h) +
      "C" + p(x,y+h-bend) + " " + p(x,y+h/2) + " " + p(x,y) + "Z",
      color: palette[crypto.randomInt(palette.length)], layer });
  }
  function cluster(cells, cx, cy) {
    const point = transform(cx, cy);
    let shard = crypto.randomInt(3);
    for (const [x, y] of cells) {
      const layer = shard++ % 3;
      blob(point, x*5, y*5, layer);
      blob(point, x*5+2.5, y*5, (layer+1)%3);
      // Complementary twins share the same local bounding region and palette.
      if (crypto.randomInt(4) === 0) {
        blob(point, x*5, y*5, (layer+2)%3, 0.65);
        blob(point, x*5+2.5, y*5, layer, -0.65);
      }
    }
  }
  for (let i = 0; i < answer.length; i++) {
    const cells = [];
    FONT[answer[i]].split("/").forEach((row,y) => [...row].forEach((pixel,x) => { if (pixel === "1") cells.push([x,y]); }));
    cluster(cells, 35+i*45, 58+8*Math.sin(i+phase));
  }
  // Connected pseudo-glyphs use the same paired density and affine generator.
  for (let i = 0; i < 8; i++) {
    const cells = new Map(); let x = crypto.randomInt(5), y = crypto.randomInt(7);
    for (let step = 0; step < 45; step++) {
      cells.set(x+":"+y, [x,y]);
      const axis = crypto.randomInt(2), delta = crypto.randomInt(2) ? 1 : -1;
      if (axis) x = Math.max(0,Math.min(4,x+delta)); else y = Math.max(0,Math.min(6,y+delta));
    }
    cluster([...cells.values()], 18+(i%7)*43, i%2 ? 85 : 30);
  }
  for (let i = paths.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1); [paths[i], paths[j]] = [paths[j], paths[i]];
  }
  return { width: 310, height: 120, background: "#f1f5f9", palette, paths,
    noise: { layerOffsets, fps: 60, particles: 300, seed: crypto.randomBytes(4).readUInt32BE(), opacity: 0.32 } };
}

function generateVisual(secret, challengeId) {
  const answer = Array.from({ length: 6 }, () => ALPHABET[crypto.randomInt(ALPHABET.length)]).join("");
  return { answerHash: answerHash(secret, answer, challengeId), instructions: renderAnswer(answer) };
}
module.exports = { generateVisual, renderAnswer, answerHash, ALPHABET };
