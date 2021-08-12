#!/usr/bin/env python3

import os
import re
import sys
import json
import urllib
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option, validators


def check_key(k, d):
    return k in d and d[k]


@Configuration()
class CheckAppCompatibilityCommand(StreamingCommand):
    app_id_regex = re.compile('(?<=app\/)\d+')
    splunkbase_api_uri = 'https://splunkbase.splunk.com/api/v1/app/{}/'\
                         '?include=releases,releases.splunk_compatibility'

    target_version = Option(
        doc='''
            **Syntax:** **fieldname=***<fieldname>*
            **Description:** The Splunk version you would like to upgrade to''',
        require=True)

    def stream(self, records):
        target_version = '.'.join(self.target_version.split('.')[:2])
        for record in records:
            record['status'] = ''
            record['already_compatible'] = 'no'

            if not check_key('version', record):
                record['already_compatible'] = 'undecided'
                record['status'] = '🛑 No version available. Therefore were\'re not able to check for updates.'
                yield record
                continue

            # if no update page is available we have to resolve the app id via splunk's REST API
            if not check_key('update.homepage', record) and check_key('title', record):
                uri = f"https://apps.splunk.com/apps/id/{record['title']}"
                try:
                    rdr = urllib.request.urlopen(uri)
                except Exception as e:
                    record['already_compatible'] = 'undecided'
                    record['status'] = f"🛑 Wasn\'t able to retrieve the app id via {uri}: {str(e)}."\
                                    "\n    Might be an unpublished app."
                    yield record
                    continue

                if not rdr.url:
                    record['already_compatible'] = 'undecided'
                    record['status'] = '🛑 Retrieving the app id via update.homepage as well as '\
                                    'generic title resolvement failed.'
                    yield record
                    continue

                app_id = re.search(self.app_id_regex, rdr.url)
            else:
                app_id = re.search(self.app_id_regex, record['update.homepage'])

            if not app_id:
                record['already_compatible'] = 'undecided'
                record['status'] = f"🛑 Can\'t identify App ID in update.homepage ({record['update.homepage']})"
                yield record
                continue

            request_uri = self.splunkbase_api_uri.format(app_id.group())
            try:
                api_response = json.load(urllib.request.urlopen(request_uri))
            except Exception as e:
                record['already_compatible'] = 'undecided'
                record['status'] = f"🛑 Wasn\'t able to retrieve the app id via {request_uri}: {str(e)}."
                yield record
                continue

            if not check_key('releases', api_response):
                record['already_compatible'] = 'undecided'
                record['status'] = f"🛑 API response for {request_uri} did not contain any releases."
                yield record
                continue

            version_found = False
            suitable_version = ''
            for release in api_response['releases'][::-1]:

                # Check if the currently installed version does fit
                if release['title'] == record['version']:
                    version_found = True
                    if target_version in release['splunk_compatibility']:
                        suitable_version = record['version']
                        record['status'] = f"✅ App ready for {self.target_version}"
                        record['already_compatible'] = 'yes'
                        break

                # Check if the a newer version would be available which fulfills the needs
                if target_version in release['splunk_compatibility']:
                    suitable_version = release['title']
                    record['status'] = f"🛑 App should be updated to at least {release['title']} ({release['path']})"
                    if version_found:
                        break

            if not suitable_version:
                record['status'] = f"🛑 Wasn't able to find a suitable version for this app."
                yield record
                continue

            # Check if there would be a version to upgrade even if it's not necessary
            for release in api_response['releases']:
                if target_version in release['splunk_compatibility']:
                    if suitable_version == release['title']:
                        break

                    record['status'] += f"\n    could be updated to {release['title']} ({release['path']})"
                    break

            yield record


dispatch(CheckAppCompatibilityCommand, sys.argv, sys.stdin, sys.stdout, __name__)