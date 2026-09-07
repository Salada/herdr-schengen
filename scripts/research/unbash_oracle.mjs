#!/usr/bin/env node
// Offline differential oracle. It parses synthetic corpus text and emits only
// bounded structural metadata; it never evaluates or executes shell input.

import { createInterface } from "node:readline";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

const MAX_COMMAND_BYTES = 64 * 1024;
const MAX_NODES = 4096;
const MAX_DEPTH = 64;
const MAX_DIAGNOSTICS = 32;
const MAX_IR_BYTES = 16 * 1024;
const PARSE_BUDGET_MS = 5;
const TRAVERSAL_BUDGET_MS = 5;

const classifications = new Map([
  ["Script", "root"],
  ["Command", "command"],
  ["ArithmeticCommand", "command"],
  ["TestCommand", "command"],
  ["Statement", "chain"],
  ["AndOr", "chain"],
  ["Pipeline", "pipeline"],
  ["CommandExpansion", "substitution"],
  ["ArithmeticCommandExpansion", "substitution"],
  ["ArithmeticExpansion", "substitution"],
  ["ProcessSubstitution", "substitution"],
  ["SimpleExpansion", "dynamic"],
  ["ParameterExpansion", "dynamic"],
  ["Assignment", "dynamic"],
  ["BraceExpansion", "dynamic"],
  ["ExtendedGlob", "dynamic"],
  ["ArithmeticBinary", "compound"],
  ["ArithmeticFor", "compound"],
  ["ArithmeticGroup", "compound"],
  ["ArithmeticTernary", "compound"],
  ["ArithmeticUnary", "compound"],
  ["ArithmeticWord", "compound"],
  ["BraceGroup", "compound"],
  ["Case", "compound"],
  ["CaseItem", "compound"],
  ["CompoundList", "compound"],
  ["Coproc", "compound"],
  ["For", "compound"],
  ["Function", "compound"],
  ["If", "compound"],
  ["Select", "compound"],
  ["Subshell", "compound"],
  ["TestBinary", "compound"],
  ["TestGroup", "compound"],
  ["TestLogical", "compound"],
  ["TestNot", "compound"],
  ["TestUnary", "compound"],
  ["While", "compound"],
  ["AnsiCQuoted", "literal"],
  ["DoubleQuoted", "literal"],
  ["Literal", "literal"],
  ["LocaleString", "literal"],
  ["SingleQuoted", "literal"],
]);

function byteOffset(source, utf16Offset) {
  return Buffer.byteLength(source.slice(0, utf16Offset), "utf8");
}

function boundedIr(root, source) {
  const started = performance.now();
  const stack = [[root, 0]];
  const seen = new WeakSet();
  const nodes = [];
  const diagnostics = [];
  const counts = {
    command_count: 0,
    chain_count: 0,
    pipeline_count: 0,
    redirection_count: 0,
    substitution_count: 0,
    heredoc_count: 0,
    unknown_count: 0,
  };
  let visited = 0;
  let dynamic = false;
  let bounded = false;

  while (stack.length) {
    if (performance.now() - started > TRAVERSAL_BUDGET_MS) {
      diagnostics.push({ code: "TRAVERSAL_BUDGET_EXCEEDED" });
      bounded = true;
      break;
    }
    const [value, depth] = stack.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    visited += 1;
    if (visited > MAX_NODES) {
      diagnostics.push({ code: "NODE_LIMIT_EXCEEDED" });
      bounded = true;
      break;
    }
    if (depth > MAX_DEPTH) {
      diagnostics.push({ code: "DEPTH_LIMIT_EXCEEDED" });
      bounded = true;
      break;
    }
    const isWord = Number.isInteger(value.pos) && Number.isInteger(value.end) && "text" in value;
    if (typeof value.type === "string" || isWord) {
      const classification = typeof value.type === "string"
        ? (classifications.get(value.type) ?? "unknown")
        : "literal";
      const start = Number.isInteger(value.pos) ? byteOffset(source, value.pos) : 0;
      const end = Number.isInteger(value.end) ? byteOffset(source, value.end) : start;
      nodes.push({ classification, start_byte: start, end_byte: end });
      dynamic ||= classification === "dynamic" || classification === "substitution";
      if (classification === "unknown") {
        counts.unknown_count += 1;
        diagnostics.push({ code: "UNKNOWN_NODE", start_byte: start, end_byte: end });
      } else if (classification === "command") counts.command_count += 1;
      else if (classification === "chain") counts.chain_count += 1;
      else if (classification === "pipeline") counts.pipeline_count += 1;
      else if (classification === "substitution") counts.substitution_count += 1;
    }
    const isRedirect = !value.type && Number.isInteger(value.pos)
      && Number.isInteger(value.end) && typeof value.operator === "string";
    if (isRedirect) {
      counts.redirection_count += 1;
      if (value.operator === "<<" || value.operator === "<<-") counts.heredoc_count += 1;
      nodes.push({
        classification: "redirection",
        start_byte: byteOffset(source, value.pos),
        end_byte: byteOffset(source, value.end),
      });
    }
    if (diagnostics.length >= MAX_DIAGNOSTICS) {
      diagnostics.length = MAX_DIAGNOSTICS;
      bounded = true;
      break;
    }
    const entries = Object.entries(value);
    if ("parts" in value && !entries.some(([key]) => key === "parts")) entries.push(["parts", value.parts]);
    for (const [, child] of entries.reverse()) {
      if (Array.isArray(child) || (child && typeof child === "object")) {
        if (Array.isArray(child)) {
          for (let index = child.length - 1; index >= 0; index -= 1) stack.push([child[index], depth + 1]);
        } else stack.push([child, depth + 1]);
      }
    }
  }
  let ir = { schema_version: 1, nodes, node_count: visited };
  if (Buffer.byteLength(JSON.stringify(ir), "ascii") > MAX_IR_BYTES) {
    diagnostics.push({ code: "IR_SERIALIZED_LIMIT_EXCEEDED" });
    ir = { schema_version: 1, nodes: [], node_count: visited };
    bounded = true;
  }
  return { ir, counts, diagnostics, dynamic, bounded, traversal_ns: Math.round((performance.now() - started) * 1e6) };
}

if (process.argv.length !== 4 || process.argv[2] !== "--module") process.exit(2);
const { parse } = await import(pathToFileURL(process.argv[3]).href);
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });

for await (const line of lines) {
  let request;
  try {
    request = JSON.parse(line);
    const raw = request.raw_command;
    if (typeof raw !== "string") throw new Error("bad envelope");
    const bytes = Buffer.from(raw, "utf8");
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (bytes.length > MAX_COMMAND_BYTES || request.raw_byte_length !== bytes.length || request.raw_sha256 !== digest) {
      throw new Error("bad binding");
    }
    const parseStarted = performance.now();
    const tree = parse(raw);
    const parseNs = Math.round((performance.now() - parseStarted) * 1e6);
    const built = boundedIr(tree, raw);
    const errors = Array.isArray(tree.errors) ? tree.errors : [];
    const diagnosticCodes = built.diagnostics.map((item) => item.code);
    if (errors.length) diagnosticCodes.push("PARSE_ERROR");
    if (tree.pos !== 0 || tree.end !== raw.length) diagnosticCodes.push("INCOMPLETE_CONSUMPTION");
    if (built.dynamic) diagnosticCodes.push("DYNAMIC_SYNTAX");
    if (parseNs > PARSE_BUDGET_MS * 1e6) diagnosticCodes.push("PARSE_BUDGET_EXCEEDED");
    const invalid = diagnosticCodes.length > 0 || built.bounded;
    process.stdout.write(JSON.stringify({
      schema_version: 1,
      request_id: request.request_id,
      raw_sha256: request.raw_sha256,
      raw_byte_length: request.raw_byte_length,
      status: invalid ? "UNMODELED_OR_INVALID" : "COMPLETE",
      completion_state: invalid ? "invalid" : "complete",
      diagnostic_codes: diagnosticCodes.slice(0, MAX_DIAGNOSTICS),
      parser_engine: "unbash",
      parser_version: "4.0.10",
      structural_counts: built.counts,
      diagnostic_spans: built.diagnostics.filter((item) => "start_byte" in item)
        .map(({ start_byte, end_byte }) => ({ start_byte, end_byte }))
        .concat(errors.map((error) => {
          const start = byteOffset(raw, error.pos);
          return { start_byte: start, end_byte: start };
        })).slice(0, MAX_DIAGNOSTICS),
      parse_ns: parseNs,
      traversal_ns: built.traversal_ns,
      ir: built.ir,
    }) + "\n");
  } catch {
    process.stdout.write(JSON.stringify({
      schema_version: 1,
      request_id: request?.request_id ?? "",
      raw_sha256: request?.raw_sha256 ?? "",
      raw_byte_length: request?.raw_byte_length ?? 0,
      status: "UNMODELED_OR_INVALID",
      completion_state: "invalid",
      diagnostic_codes: ["ORACLE_EXCEPTION"],
      parser_engine: "unbash",
      parser_version: "4.0.10",
      structural_counts: {
        command_count: 0,
        chain_count: 0,
        pipeline_count: 0,
        redirection_count: 0,
        substitution_count: 0,
        heredoc_count: 0,
        unknown_count: 0,
      },
      diagnostic_spans: [],
      ir: { schema_version: 1, nodes: [], node_count: 0 },
    }) + "\n");
  }
}
