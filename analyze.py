
import sys
import json
import pprint
import gzip


def group_by_key(events, key_fn):
    groups = {}

    for x in events:
        key = key_fn(x)
        if not key:
            continue

        groups.setdefault(key, [])
        groups[key].append(x)

    return groups


def count_by_key(events, key_fn):
    unique = {}

    for x in events:
        key = key_fn(x)
        if not key:
            continue

        unique.setdefault(key, 0)
        unique[key] += 1

    return unique


def sort_by_count(counts):
    for k, v in reversed(sorted(counts.items(), key=lambda x: x[1])):
        yield k, v


def get_msg(x):
    return x['tags']['msg'][0] if 'msg' in x['tags'] else x['msg']


def print_server_report(f, events):
    f.write('\n\n### Events grouped by server ###\n')
    groups = group_by_key(events, lambda x: x['headers']['server'])

    def key_fn(x):
        rule = x['tags']['id'][0]
        path = x['headers']['request']['path']
        msg = get_msg(x)
        return f'{rule} {path} "{msg}"'

    for key, event in groups.items():
        f.write(f'\n# {key}\n')
        counts = count_by_key(event, key_fn)

        for msg, count in sort_by_count(counts):
            f.write(f'{msg} {count:,}\n')


def print_client_report(f, events):
    f.write('\n\n### Events grouped by client ###\n')
    groups = group_by_key(events, lambda x: x['headers'].get('client'))

    for key, event in groups.items():
        f.write(f'\n# {key}\n')
        counts = count_by_key(event, get_msg)

        for reason, count in sort_by_count(counts):
            f.write(f'"{reason}" {count:,}\n')


def print_ip_addr_report(f, events):
    f.write('\n\n### Event counts by IP addresses ###\n\n')
    counts = count_by_key(events, lambda x: x['headers'].get('client'))

    for ip_addr, count in sort_by_count(counts):
        f.write(f'{ip_addr} {count:,}\n')


def print_reason_report(f, events):
    f.write('\n\n### Event counts by block reason ###\n\n')
    counts = count_by_key(events, get_msg)

    for reason, count in sort_by_count(counts):
        f.write(f'"{reason}" {count:,}\n')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('USAGE: python analyze.py <data file> <output file>')
        sys.exit(1)

    with gzip.open(sys.argv[1], 'r') as f:
        events = json.loads(f.read())

    with open(sys.argv[2], 'w') as f:
        f.write('###### ModSecurity Blocked Events Report ######\n')
        print_server_report(f, events)
        print_client_report(f, events)
        print_ip_addr_report(f, events)
        print_reason_report(f, events)
