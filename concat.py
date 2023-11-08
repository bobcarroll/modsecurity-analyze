
import os
import sys
import json
import gzip


def scan_dir(path):
    return [os.path.join(path, x) for x in os.listdir(path) if x.endswith('.json.gz')]


def dedup(events, output):
    count = 0

    for x in events:
        key = x['hash']

        if key in output:
            count += 1
        else:
            output[key] = x

    return count


def concat_files(paths):
    events = {}
    dups = 0

    for i, x in enumerate(paths):
        with gzip.open(x, 'r') as f:
            print(f'Reading {i+1}/{len(paths)} {x}')
            dups += dedup(json.loads(f.read()), events)

    return list(events.values()), dups


def write_results(events, out_file, dups):
    with gzip.open(out_file, 'w') as f:
        f.write(json.dumps(events).encode('utf-8'))

    print(f'Wrote {len(events):,} events to {out_file}, Skipped {dups} duplicate(s)')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('USAGE: python concat.py <in dir> <out name>')
        sys.exit(1)

    paths = scan_dir(sys.argv[1])
    events, dups = concat_files(paths)
    write_results(events, sys.argv[2] + '.json.gz', dups)
