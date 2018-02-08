import urllib.parse
import base64
import struct
import binascii
import math
import argparse
import json
import os


def forgiving_b64_decode(x, pads=0):
    padded = "{}{}".format(x, "_" * pads)
    try:
        return base64.b64decode(padded, "-_")
    except binascii.Error as e:
        if pads < 2:
            return forgiving_b64_decode(x, pads + 1)
        else:
            raise e

encodings = {
    'original': bytearray,
    'signed_int': lambda x: struct.pack("q", int(x)),
    'unsigned_int': lambda x: struct.pack("Q", int(x)),
    'hex': binascii.unhexlify,
    'base64': forgiving_b64_decode,
    'ascii': lambda x: x.encode("ascii")
}


def parse(url):
    parsed_url = urllib.parse.urlparse(url)
    return {
        "query": urllib.parse.parse_qs(parsed_url.query),
        "route": parsed_url.path.split('/'),
        "url": url
    }


def cumsum(x):
    return sum(x for x in range(x + 1))


def get_urls_from(file):
    with open(file, "r") as url_file:
        return (parse(x.rstrip("\r\n ])([.\\\'\"")) for x in url_file.readlines())


def categorize(url):
    return "{} {}".format(len(url['route']), " ".join(sorted(url['query'].keys())))


def try_decode(sample, encoding):
    try:
        return (sample, encoding(sample))
    except Exception:
        return None

def smart_utf(x):
    leading_zero = 0
    while len(x) > leading_zero and x[leading_zero] == 0:
        leading_zero += 1
    trailing_zero = len(x) - 1
    while trailing_zero >= leading_zero and x[trailing_zero] == 0:
        trailing_zero -= 1
    if trailing_zero == leading_zero+1:
        return "NULL"
    x = x[leading_zero:trailing_zero+1]
    result = []
    for y in x:
        if y < 128:
            try:
                result += chr(y)
            except:
                pass
        else:
            result += "?"
    return "".join(result)

def extract_groups(urls):
    groups = {}
    for url in urls:
        category = categorize(url)
        group = groups.get(category, {'urls': [], 'collection': {}})
        group['urls'].append(url["url"])
        for x in url['query']:
            values = group['collection'].get(x, [])
            values.append(url['query'][x][0])
            group['collection'][x] = values
        for i in range(0, len(url['route'])):
            x = "@{}".format(i)
            values = group['collection'].get(x, [])
            values.append(url['route'][i])
            group['collection'][x] = values
        groups[category] = group
    return groups


def decode(groups):
    decoded = {}
    for group_name in groups:
        group = groups[group_name]
        groups[group_name] = {x: group['collection'][x] for x in group['collection'] if
                              len(set(group['collection'][x])) > 1}
        decoded[group_name] = {}
    for group_name in groups:
        group = groups[group_name]
        for element in group:
            decoded[group_name][element] = {}
            for encoding in encodings:
                decodings = [try_decode(sample, encodings[encoding]) for sample in group[element]]
                decodings = [x for x in decodings if x]
                if len(decodings) > 1:
                    decoded[group_name][element][encoding] = decodings
    return decoded


def summarize(decoded, urls):
    results = {}
    for group in decoded:
        results[group] = { "fields": {}, "urls": urls[group]}
        for field in decoded[group]:
            results[group]["fields"][field] = {}
            for encoding in decoded[group][field]:  # Each encoding / field combo
                originals = [x[0] for x in decoded[group][field][encoding]]
                elements = [x[1] for x in decoded[group][field][encoding]]
                max_len = max(len(x) for x in elements)
                for i in range(len(elements)):
                    elements[i] = b'\x00' * (max_len - len(elements[i])) + elements[i]
                pmfs = []
                for j in range(max_len):  # Finds min/max/range of each field
                    pmfs.append({})
                    for element in elements:
                        pmfs[j][element[j]] = pmfs[j].get(element[j], 0) + 1
                    for support in pmfs[j]:
                        pmfs[j][support] /= len(elements)
                entropy = 0
                for j in range(max_len):
                    entropy += -1 * sum(pmfs[j][support] * math.log(pmfs[j][support], 2) for support in pmfs[j])
                results[group]["fields"][field][encoding] = {
                    "n_elements": len(elements),
                    "entropy": entropy,
                    "elements": [binascii.hexlify(x) for x in elements],
                    "originals": originals
                }
    return results


def make_report(summary):
    report = {}
    for group in summary:
        report[group] = {
            "urls": summary[group]["urls"],
            "fields": {}
        }
        group_entropy = 0
        for field in summary[group]["fields"]:
            report[group]["fields"][field] = []
            entropy_frontier = {}
            for encoding in summary[group]["fields"][field]:
                n_elem = summary[group]["fields"][field][encoding]['n_elements']
                entro = summary[group]["fields"][field][encoding]['entropy']
                if n_elem not in entropy_frontier or entro < entropy_frontier[n_elem]["entropy"]:
                    entropy_frontier[n_elem] = summary[group]["fields"][field][encoding]
                    entropy_frontier[n_elem]["encoding"] = encoding
            sorted_frontier = [x for x in entropy_frontier]; sorted_frontier.sort(reverse=True)
            if len(sorted_frontier) == 0:
                continue
            entro = entropy_frontier[sorted_frontier[0]]["entropy"]
            for y in sorted_frontier[1:]:
                if entropy_frontier[y]["entropy"] >= entro:
                    entropy_frontier.pop(y)
                else:
                    entro = entropy_frontier[y]["entropy"]
            sorted_frontier = [x for x in entropy_frontier]; sorted_frontier.sort()
            min_entropy = None
            for frontier_index in sorted_frontier:
                frontier_element = entropy_frontier[frontier_index]
                tokens = frontier_element["elements"]
                originals = frontier_element["originals"]
                encoded_samples = []
                for token_index in range(0, len(tokens)):
                    token = tokens[token_index]
                    original = originals[token_index]
                    bytes = binascii.unhexlify(token)
                    as_utf = smart_utf(bytes)
                    encoded_samples.append({
                        "hexlified": ' '.join('{:02x}'.format(x) for x in binascii.unhexlify(token)),
                        "ascii": as_utf,
                        "original": original
                    })
                report[group]["fields"][field].append({
                    "count": frontier_index,
                    "entropy": frontier_element["entropy"],
                    "encoding": frontier_element["encoding"],
                    "samples": encoded_samples
                })
                min_entropy = frontier_element["entropy"] if min_entropy == None or min_entropy > frontier_element["entropy"] else min_entropy
            group_entropy += min_entropy
        report[group]["entropy"] = group_entropy
    return report


def report_to_text(report, n_elem_to_show, n_url_to_show):
    lines = []
    for group in report:
        lines += "==== %s ====\n     Sample URLs:\n" % group
        for url in report[group]["urls"][:n_url_to_show]:
            lines += "     * %s\n" % url
        lines += "\n     Entropy: %5.1f\n" % report[group]["entropy"]
        for field in report[group]["fields"]:
            for f in report[group]["fields"][field]:
                lines += "     **** %s - %s ****\n" % (field, f["encoding"])
                lines += "          Token Entropy: %5.2f\n" % f["entropy"]
                lines += "          Decode Count:   %d\n" % f["count"]
                lines += "          Sample Tokens:\n"
                for sample in f["samples"][:n_elem_to_show]:
                    lines += "              %s\n" % sample["original"]
                    lines += "              %s\n" % sample["hexlified"]
                    lines += "              %s\n\n" % sample["ascii"]

    return "".join(lines)


def report_to_json(report):
    return json.dumps(report)


def process(urls_path):
    groups = extract_groups(get_urls_from(urls_path))
    urls = { name: groups[name]['urls'] for name in groups }
    decoded = decode(groups)
    summary = summarize(decoded, urls)
    report = make_report(summary)
    return report

parser = argparse.ArgumentParser(description='Computes entropy of URLs')
parser.add_argument('-s','--search', help='Input is a directory. Write multiple outputs to this directory.', default=None)
parser.add_argument('-t','--text', help='Text output. (Default is JSON.)', action="store_true")
parser.add_argument('-e','--elem', help='Number of token samples to print (text only)', default=5, type=int)
parser.add_argument('-u','--url', help='Number of url samples to print (text only)', default=5, type=int)
parser.add_argument('file', nargs=1, help='File containing URL samples')
args = parser.parse_args()

if args.search:
    dir = args.file[0]
    for f in os.listdir(dir):
        path = os.path.join(dir, f)
        report = process(path)
        for group in report:
            ent = report[group]["entropy"]
            print("%s,%s,%5.2f" % (path, group, report[group]["entropy"]))
        path_prefix = os.path.join(args.search, f)
        if args.text:
            with open("%s.txt" % path_prefix, "w") as of:
                of.write(report_to_text(report, args.elem, args.url))
        else:
            with open("%s.json" % path_prefix, "w") as of:
                of.write(report_to_json(report))
else:
    report = process(args.file[0])
    if args.text:
        print(report_to_text(report, args.elem, args.url))
    else:
        print(report_to_json(report))
