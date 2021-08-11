import os
import sys
import time
import re
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

uri = 'https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats'
splunk_versions_regex = re.compile('(?<=<option value=")(\d+\.\d+\.\d+)')

@Configuration()
class GetSplunkVersionsCommand(GeneratingCommand):

    # I know it's quite a hack. If somebody knows a better way build a PR
    def generate(self):
        try:
            cnt = str(urllib.request.urlopen(uri).read())
        except Exception as e:
            raise RuntimeError(f"Wasn't able to fetch splunk versions using {uri}")

        for version in re.findall(splunk_versions_regex, cnt)[::-1]:
            yield {'_time': time.time(), '_raw': version, 'version': version}


dispatch(GetSplunkVersionsCommand, sys.argv, sys.stdin, sys.stdout, __name__)
