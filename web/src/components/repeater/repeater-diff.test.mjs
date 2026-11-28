import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
require("ts-node").register({
  transpileOnly: true,
  compilerOptions: { module: "CommonJS", moduleResolution: "Node10" },
});
const { countDiff, diffLines, prettyBody } = require("./repeater-diff.ts");

test("diffLines: 单行变更产出 remove+add", () => {
  const diff = diffLines("a\nb\nc", "a\nX\nc");
  assert.deepEqual(
    diff.map((l) => l.kind),
    ["same", "remove", "add", "same"],
  );
  assert.equal(diff[1].text, "b");
  assert.equal(diff[2].text, "X");
});

test("diffLines: 相同输入无任何增删", () => {
  const diff = diffLines("x\ny", "x\ny");
  assert.equal(diff.filter((l) => l.kind !== "same").length, 0);
});

test("diffLines: 追加行在尾部", () => {
  const diff = diffLines("a\nb", "a\nb\nc");
  assert.deepEqual(
    diff.map((l) => l.kind),
    ["same", "same", "add"],
  );
  assert.equal(diff[2].text, "c");
});

test("diffLines: 删除行在尾部", () => {
  const diff = diffLines("a\nb\nc", "a\nb");
  assert.deepEqual(
    diff.map((l) => l.kind),
    ["same", "same", "remove"],
  );
});

test("countDiff: 统计增删同", () => {
  const stats = countDiff(diffLines("a\nb\nc", "a\nX\nc"));
  assert.deepEqual(stats, { added: 1, removed: 1, same: 2 });
});

test("prettyBody: JSON 缩进美化，非 JSON 原样返回", () => {
  assert.equal(prettyBody('{"a":1}'), '{\n  "a": 1\n}');
  assert.equal(prettyBody("plain text"), "plain text");
});

test("diffLines: 空 vs 单行", () => {
  const diff = diffLines("", "x");
  assert.deepEqual(
    diff.map((l) => l.kind),
    ["add"],
  );
});
