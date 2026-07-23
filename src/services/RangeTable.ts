// src/services/RangeTable.ts
//
// Packed, cache-friendly replacement for Array<[number, number]> sorted
// range lists (IPv4 CIDR/range data merged into disjoint [start,end]
// pairs) - used by ListManager, DatasetLoader and AsnIndex wherever a
// binary-searchable range table is needed on the per-connection hot path.
//
// WHY: a boxed Array<[number,number]> costs ~56-100+ bytes per entry in V8
// (an element pointer into the outer array + a 2-element array object + two
// boxed Number values) versus 8 bytes/entry for two parallel Uint32Arrays
// holding the same data - a 5-10x reduction for datasets that can run into
// the millions of ranges. Binary search is also faster this way: the
// "start" values being compared are contiguous in memory (one cache line
// covers 16 comparisons' worth of starts) instead of scattered across many
// separately-allocated small array objects.
export function binarySearchIndex(starts: Uint32Array, ends: Uint32Array, num: number): number {
  let lo = 0, hi = starts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const s = starts[mid];
    if (num < s) { hi = mid - 1; continue; }
    if (num > ends[mid]) { lo = mid + 1; continue; }
    return mid;
  }
  return -1;
}

export class RangeTable {
  private starts: Uint32Array;
  private ends: Uint32Array;

  private constructor(starts: Uint32Array, ends: Uint32Array) {
    this.starts = starts;
    this.ends = ends;
  }

  static readonly EMPTY = new RangeTable(new Uint32Array(0), new Uint32Array(0));

  get size(): number {
    return this.starts.length;
  }

  // Builds a table from unsorted, possibly-overlapping [start,end] pairs -
  // sorts and merges adjacent/overlapping ranges into the minimal disjoint
  // set, same semantics every existing hand-rolled merge loop in this
  // project already implements.
  static fromPairs(pairs: Array<[number, number]>): RangeTable {
    if (pairs.length === 0) return RangeTable.EMPTY;
    const sorted = pairs.slice().sort((a, b) => a[0] - b[0]);
    const mergedStarts: number[] = [];
    const mergedEnds: number[] = [];
    for (const [start, end] of sorted) {
      const lastIdx = mergedEnds.length - 1;
      if (lastIdx >= 0 && start <= mergedEnds[lastIdx] + 1) {
        if (end > mergedEnds[lastIdx]) mergedEnds[lastIdx] = end;
      } else {
        mergedStarts.push(start);
        mergedEnds.push(end);
      }
    }
    return new RangeTable(Uint32Array.from(mergedStarts), Uint32Array.from(mergedEnds));
  }

  // Builds directly from rows already sorted by start_ip (e.g. a bulk
  // "ORDER BY start_ip" DB read) - still merges adjacent/overlapping pairs
  // (rows from different sources aren't guaranteed disjoint against each
  // other) but skips the initial sort since the input is already ordered.
  static fromSortedPairs(starts: ArrayLike<number>, ends: ArrayLike<number>): RangeTable {
    const n = starts.length;
    if (n === 0) return RangeTable.EMPTY;
    const mergedStarts: number[] = [];
    const mergedEnds: number[] = [];
    for (let i = 0; i < n; i++) {
      const start = starts[i], end = ends[i];
      const lastIdx = mergedEnds.length - 1;
      if (lastIdx >= 0 && start <= mergedEnds[lastIdx] + 1) {
        if (end > mergedEnds[lastIdx]) mergedEnds[lastIdx] = end;
      } else {
        mergedStarts.push(start);
        mergedEnds.push(end);
      }
    }
    return new RangeTable(Uint32Array.from(mergedStarts), Uint32Array.from(mergedEnds));
  }

  has(num: number): boolean {
    return binarySearchIndex(this.starts, this.ends, num) !== -1;
  }

  // Returns the matching [start,end] pair, or null - used where the caller
  // needs to report the actual matched range (e.g. rendering it back out as
  // "a.b.c.d-w.x.y.z").
  findRange(num: number): [number, number] | null {
    const idx = binarySearchIndex(this.starts, this.ends, num);
    return idx === -1 ? null : [this.starts[idx], this.ends[idx]];
  }
}
