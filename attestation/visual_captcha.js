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
  const palette = ["#334155", "#475569", "#536479"];
  const paths = [];
  const phase = random(0, Math.PI * 2);
  for (let i = 0; i < answer.length; i++) {
    const angle = random(-28, 28) * Math.PI / 180;
    const shear = random(-0.14, 0.14), scale = random(0.9, 1.08), wave = random(0.8, 2.3);
    const point = (x, y) => {
      x = (x - 12.5) * scale + shear * y + wave * Math.sin(y / 8 + phase);
      y -= 17.5;
      return [(35 + i * 45 + x * Math.cos(angle) - y * Math.sin(angle)).toFixed(2),
        (58 + 8 * Math.sin(i + phase) + x * Math.sin(angle) + y * Math.cos(angle)).toFixed(2)].join(" ");
    };
    FONT[answer[i]].split("/").forEach((row, y) => {
      [...row].forEach((pixel, x) => {
        if (pixel !== "1") return;
        const size = random(4.5, 5.5), left = x * 5, top = y * 5;
        paths.push({ d: `M${point(left, top)}L${point(left + size, top)}L${point(left + size, top + size)}L${point(left, top + size)}Z`,
          color: palette[crypto.randomInt(palette.length)], width: random(0.3, 1.1), fill: true });
      });
    });
  }
  const curveCount = crypto.randomInt(12, 19);
  for (let i = 0; i < curveCount; i++) {
    const p = () => `${random(0, 310).toFixed(1)} ${random(15, 105).toFixed(1)}`;
    paths.push({ d: `M${p()}C${p()} ${p()} ${p()}`, color: palette[crypto.randomInt(palette.length)], width: random(0.4, 1.5), fill: false });
  }
  // Shuffle paths so no semantic character grouping/order is transmitted.
  for (let i = paths.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1); [paths[i], paths[j]] = [paths[j], paths[i]];
  }
  return { width: 310, height: 120, background: "#f1f5f9", palette, paths,
    noise: { fps: 30, particles: 300, seed: crypto.randomBytes(4).readUInt32BE(), opacity: 0.32 } };
}

function generateVisual(secret, challengeId) {
  const answer = Array.from({ length: 6 }, () => ALPHABET[crypto.randomInt(ALPHABET.length)]).join("");
  return { answerHash: answerHash(secret, answer, challengeId), instructions: renderAnswer(answer) };
}
module.exports = { generateVisual, renderAnswer, answerHash, ALPHABET };
