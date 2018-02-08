import os
import json
import email
import re

url_re = re.compile("http[s]?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]+")
urls = set()
email_directory = "emails"
parser = email.parser.BytesParser()


def extract(msg):
    result = [msg]
    while any(x.is_multipart() for x in result):
        for i, e in enumerate(result):
            if e.is_multipart():
                result.pop(i)
                for payload in e.get_payload():
                    result.append(payload)
                break
    return [(e.get_content_type(), e.get_payload()) for e in result]


def decode(encoding, body):
    if encoding in ['text/plain', 'text/html']:
        body = body.replace("=\r\n", "").replace("\r\n", " ")
        return body
    return " "


for path in os.listdir(email_directory):
    with open(os.path.join(email_directory, path), "rb") as f:
        email_contents = bytes(json.load(f)['raw'], "ascii")
        msg = parser.parsebytes(email_contents)
        encoded_bodies = extract(msg)
        body = "".join(decode(e, b) for e, b in encoded_bodies)
        urls.update(url_re.findall(body))

with open("urls.txt", "w") as out_file:
    for url in urls:
        out_file.write("{}\n".format(url))