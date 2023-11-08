
import os
import sys
import re
import json
import hashlib
import gzip

line_pattern = re.compile(
    r'(\d{4}\/\d{2}\/\d{2}) (\d{2}:\d{2}:\d{2}) \[([A-Za-z]+)\] (\d+#\d+): ([*]\d+)( \[client [^]]+\])? ModSecurity: ([^[]+) (.*)')
headers_pattern = re.compile(r', ([^:]+): ([^,]+)')
request_pattern = re.compile(r'"([^ ]+) ([^ ]+) ([^ ]+)"')


def pivot_tags(tags):
    results = {}

    for x in tags:
        key, value = x

        if key in results:
            results[key].append(value)
        else:
            results[key] = [value]

    return results


def parse_line(log_name, line):
    m = line_pattern.match(line)
    if not m:
        return line

    fields = {'date': m[1],
              'time': m[2],
              'level': m[3],
              'process': m[4],
              'request': m[5],
              'msg': m[7],
              'tags': pivot_tags(re.findall(r'\[([^ ]+) "?([^"]+)"?\] ', m[8])),
              'headers': {k:v for k, v in headers_pattern.findall(m[8])},
              'hash': hashlib.md5(line.encode('utf-8')).hexdigest(),
              'log_name': log_name}

    if 'request' in fields['headers']:
        rm = request_pattern.findall(fields['headers']['request'])
        fields['headers']['request'] = {
            'method': rm[0][0],
            'path': rm[0][1],
            'version': rm[0][2]}

    return fields


def read_log(path):
    if path.endswith('.gz'):
        f = gzip.open(path, 'rb')
    else:
        f = open(path, 'rb')

    lines = (x.decode('latin-1') for x in f.readlines())
    f.close()

    log_name = os.path.basename(path)
    return [parse_line(log_name, x.strip()) for x in lines if 'ModSecurity' in x]


def partition_results(events):
    parsed = []
    failed = []

    for x in events:
        if isinstance(x, str):
            failed.append(x)
        else:
            parsed.append(x)

    return parsed, failed


def write_results(events, out_file, err_file):
    parsed, failed = partition_results(events)

    with gzip.open(out_file, 'w') as f:
        f.write(json.dumps(parsed).encode('utf-8'))

    if len(failed):
        with open(err_file, 'w') as f:
            for x in failed:
                f.write(x + '\n')

    print(f'Wrote {out_file}, Parsed: {len(parsed)}, Failed: {len(failed)}')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('USAGE: python parse.py <log file> <out dir>')
        sys.exit(1)

    try:
        os.mkdir(sys.argv[2])
    except FileExistsError:
        pass

    out_file = os.path.join(sys.argv[2], sys.argv[1] + '.json.gz')
    err_file = os.path.join(sys.argv[2], sys.argv[1] + '.failed')

    events = read_log(sys.argv[1])
    write_results(events, out_file, err_file)
