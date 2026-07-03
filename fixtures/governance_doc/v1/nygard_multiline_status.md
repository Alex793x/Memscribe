# 12. Choose a diff algorithm

## Status

Accepted

Amended by [15. Refine diff algorithm](0015-refine-diff.md)

## Context

We need a diff algorithm for large files.

## Decision

Use histogram diff.

## Consequences

Faster diffs on large files.
