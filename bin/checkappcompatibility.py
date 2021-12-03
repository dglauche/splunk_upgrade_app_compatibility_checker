#!/usr/bin/env python3

import os
import re
import sys
import json
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators

def check_key(k, d):
    return k in d and d[k]

enterprise_security_apps = [
    'DA-ESS-AccessProtection', 'DA-ESS-EndpointProtection', 'DA-ESS-IdentityManagement', 'DA-ESS-NetworkProtection',
    'DA-ESS-NetworkProtection', 'DA-ESS-ThreatIntelligence', 'SA-AccessProtection', 'SA-AuditAndDataProtection',
    'SA-EndpointProtection', 'SA-IdentityManagement', 'SA-NetworkProtection', 'SA-ThreatIntelligence', 'SA-UEBA',
    'SA-Utils'
]

itsi_apps = [
    'DA-ITSI-APPSERVER', 'DA-ITSI-DATABASE', 'DA-ITSI-EUEM', 'DA-ITSI-LB', 'DA-ITSI-OS', 'DA-ITSI-OS',
    'DA-ITSI-STORAGE', 'DA-ITSI-VIRTUALIZATION', 'DA-ITSI-WEBSERVER', 'SA-IndexCreation', 'SA-ITOA', 'SA-ITSI-ATAD',
    'SA-ITSI-CustomModuleViz', 'SA-ITSI-Licensechecker', 'SA-ITSI-MetricAD', 'SA-UserAccess'
]

@Configuration(requires_preop=False)
class CheckAppCompatibilityCommand(ReportingCommand):
    app_id_regex = re.compile('(?<=app\/)\d+')
    splunkbase_api_uri = 'https://splunkbase.splunk.com/api/v1/app/{}/'\
                         '?include=releases,releases.splunk_compatibility'

    target_version = Option(
        doc='''
            **Syntax:** **target_version=***<targeted splunk version>*
            **Description:** The Splunk version you would like to upgrade to''',
        require=True)

    cloud_compatibility_required = Option(
        doc='''
                **Syntax:** **splunk_cloud_comp_required=***<true/false>*
                **Description:** The Splunk version you would like to upgrade to''',
        validate=validators.Boolean(),
        default=False,
        require=False
    )

    @Configuration()
    def map(self, records):
        return records

    def reduce(self, records):
        import concurrent.futures
        target_version = '.'.join(self.target_version.split('.')[:2])

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for record in records:
                futures.append(
                    executor.submit(self.check_version, record=record)
                )

            apps = []
            for future in concurrent.futures.as_completed(futures):
                apps.append(future.result())

            # let's take the result for the premium apps itself and copy it to the apps shipped with them
            premium_apps = {
                'SplunkEnterpriseSecuritySuite': enterprise_security_apps,
                'itsi': itsi_apps
            }
            for premium_app, packaged_apps in premium_apps.items():
                try:
                    premium_app_obj = list(filter(lambda res: res['title'] == premium_app, apps))[0]
                    for app in apps:
                        if app['title'] in packaged_apps:
                            app['status'] = premium_app_obj['status']
                            app['already_compatible'] = premium_app_obj['already_compatible']

                except Exception as e:
                    pass

            for app in apps:
                yield app

    def check_version(self, record):
        record['status'] = ''
        record['already_compatible'] = 'no'
        target_version = '.'.join(self.target_version.split('.')[:2])

        # the result of packaged apps of premium apps will be copied at the end so there is no need to check something
        if record['title'] in enterprise_security_apps:
            return record

        if record['title'] in itsi_apps:
            return record

        # if the currently installed app does not provide any version information we are not able to check anything
        if not check_key('version', record):
            record['already_compatible'] = 'undecided'
            record['status'] = '🛑 No version information available. Therefore were\'re not able to check for updates.'
            return record

        # if no update page is available we have to resolve the app id via splunk's REST API
        if not check_key('update.homepage', record) and check_key('title', record):
            uri = f"https://apps.splunk.com/apps/id/{record['title']}"

            try:
                rdr = urllib.request.urlopen(uri)
            except Exception as e:
                record['already_compatible'] = 'undecided'
                record['status'] = f"🛑 Wasn\'t able to retrieve the app id via {uri}: {str(e)}." \
                                   "\n    Might be an unpublished app."
                return record

            if not rdr.url:
                record['already_compatible'] = 'undecided'
                record['status'] = '🛑 Retrieving the app id via update.homepage as well as ' \
                                   'generic title resolvement failed.'
                return record

            app_id = re.search(self.app_id_regex, rdr.url).group()
        else:
            app_id = re.search(self.app_id_regex, record['update.homepage']).group()

        # as there was no way to identify the App ID we can't check anything
        if not app_id:
            record['already_compatible'] = 'undecided'
            record['status'] = f"🛑 Can\'t identify App ID in update.homepage ({record['update.homepage']})"
            return record

        request_uri = self.splunkbase_api_uri.format(app_id)
        try:
            api_response = json.load(urllib.request.urlopen(request_uri))
        except Exception as e:
            record['already_compatible'] = 'undecided'
            record['status'] = f"🛑 Wasn\'t able to retrieve the app id via {request_uri}: {str(e)}."
            return record

        if not check_key('releases', api_response):
            record['already_compatible'] = 'undecided'
            record['status'] = f"🛑 API response for {request_uri} did not contain any releases."
            return record

        installed_version_found = False
        suitable_version = ''
        # Looping through all releases oldest first
        for release in api_response['releases'][::-1]:

            # Check if the currently installed version does fit
            if release['title'] == record['version']:
                installed_version_found = True
                if target_version in release['splunk_compatibility']:
                    if self.cloud_compatibility_required and \
                            'Splunk Cloud' not in release['product_compatibility']:
                        break
                    suitable_version = record['version']
                    record['status'] = f"✅ App ready for {self.target_version}"
                    record['already_compatible'] = 'yes'
                    break

            # Check if the a newer version would be available which fulfills the needs
            if self.cloud_compatibility_required and 'Splunk Cloud' not in release['product_compatibility']:
                continue

            if self.target_version in release['splunk_compatibility']:
                suitable_version = release['title']
                record['status'] = f"🛑 App should be updated to at least {release['title']} ({release['path']})"
                if installed_version_found:
                    break

        if not suitable_version:
            record['status'] = f"🛑 Wasn't able to find a suitable version for this app."
            return record

        # Check if there would be a version to upgrade even if it's not necessary
        for release in api_response['releases']:
            if target_version in release['splunk_compatibility']:
                if suitable_version == release['title']:
                    return record

                if self.cloud_compatibility_required and 'Splunk Cloud' not in release['product_compatibility']:
                    continue

                record['status'] += f"\n    could be updated to {release['title']} ({release['path']})"
                break

        return record


dispatch(CheckAppCompatibilityCommand, sys.argv, sys.stdin, sys.stdout, __name__)
