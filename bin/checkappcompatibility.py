#!/usr/bin/env python3

import os
import re
import sys
import json
import urllib.request
import concurrent.futures

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators
from bs4 import BeautifulSoup
from packaging import version

INTERNAL_APPS = [
	'alert_logevent', 'alert_webhook', 'appsbrowser', 'introspection_generator_addon',
	'search', 'splunk-dashboard-studio', 'splunk_archiver', 'splunk_gdi', 'splunk_instrumentation',
	'splunk_monitoring_console', 'splunk_rapid_diag', 'splunk_secure_gateway', 'Splunk_TA_ueba',
    'splunk_metrics_workspace', 'launcher', 'learned', 'legacy', 'splunk_httpinput', 'splunk_internal_metrics',
    'SplunkForwarder', 'SplunkLightForwarder', 'journald_input'
]

ENTERPRISE_SECURITY_APPS = [
	'DA-ESS-AccessProtection', 'DA-ESS-EndpointProtection', 'DA-ESS-IdentityManagement', 'DA-ESS-NetworkProtection',
	'DA-ESS-NetworkProtection', 'DA-ESS-ThreatIntelligence', 'SA-AccessProtection', 'SA-AuditAndDataProtection',
	'SA-EndpointProtection', 'SA-IdentityManagement', 'SA-NetworkProtection', 'SA-ThreatIntelligence', 'SA-UEBA',
	'SA-Utils', 'SplunkEnterpriseSecuritySuite'
]

ITSI_APPS = [
	'DA-ITSI-APPSERVER', 'DA-ITSI-DATABASE', 'DA-ITSI-EUEM', 'DA-ITSI-LB', 'DA-ITSI-OS', 'DA-ITSI-OS',
	'DA-ITSI-STORAGE', 'DA-ITSI-VIRTUALIZATION', 'DA-ITSI-WEBSERVER', 'SA-IndexCreation', 'SA-ITOA', 'SA-ITSI-ATAD',
	'SA-ITSI-CustomModuleViz', 'SA-ITSI-Licensechecker', 'SA-ITSI-MetricAD', 'SA-UserAccess'
]

BASE_APPS = [
    'all_forwarder_outputs_route_onprem_and_cloud', 'all_app_props', 'all_deploymentclient', 'all_deploymentclient',
    'all_indexer_base', 'all_indexes', 'all_search_base', 'dept_app_inputs', 'full_license_server', 'indexer_volume_indexes',
    'indexer_volume_indexes', 'search_bundle_size_distsearch', 'search_volume_indexes', 'cluster_forwarder_outputs',
    'cluster_indexer_base', 'cluster_search_base', 'master_deploymentclient', 'multisite_master_base',
    'site_n_indexer_base'
]

GITHUB_ISSUE_URL = 'https://github.com/dglauche/splunk_upgrade_app_compatibility_checker/issues'
SPLUNKBASE_URL = 'https://splunkbase.splunk.com/api/v1/app/?limit={}&offset={}' + \
                '&include=releases,releases.content,releases.splunk_compatibility,releases.cim_compatibility,' + \
                'release,release.content,release.cim_compatibility,release.splunk_compatibility'

ES_ITSI_COMPAT_URL = 'https://docs.splunk.com/Documentation/VersionCompatibility/current/Matrix/CompatMatrix'


@Configuration(requires_preop=False)
class CheckAppCompatibilityCommand(ReportingCommand):
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
                **Description:** Defines if the check should consider Splunk Cloud compatibility''',
        validate=validators.Boolean(),
        default=False,
        require=False
    )

    threat_baseapp_as_compatible = Option(
        doc='''
                **Syntax:** **threat_baseapp_as_compatible=***<true/false>*
                **Description:** We can not ensure that baseapps are compatible with a new splunk version. Therefore the user can decide on his/her own.''',
        validate=validators.Boolean(),
        default=False,
        require=False
    )

    @Configuration()
    def map(self, records):
        return records

    def reduce(self, records):
        splunkbase_apps = self.get_all_apps()
        premium_app_compatibility = self.get_premium_app_compatibility()
        
        for installed_app in records:
            yield self.check_version(installed_app, splunkbase_apps, premium_app_compatibility)

    def get_apps(self, limit=100, offset=0):
        url = SPLUNKBASE_URL.format(limit, offset)
        data = json.load(urllib.request.urlopen(url))
        return data['results']


    def get_all_apps(self):
        limit = 100
        offset = 0
        total_apps = 10000

        futures = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            while (offset + limit < total_apps):
                futures.append(
                    executor.submit(self.get_apps, offset=offset, limit=limit)
                )
                offset = offset + limit

        apps = {}
        for future in concurrent.futures.as_completed(futures):
            for app in future.result():
                apps[app['uid']] = app

        return apps


    def get_premium_app_compatibility(self):
        req = urllib.request.urlopen(ES_ITSI_COMPAT_URL)
        bs = BeautifulSoup(req, 'html.parser')

        premium_app_compatibility = {}
        for table in bs.find_all('table'):
            tbody = table.find('tbody')

            if not tbody:
                break

            rows = tbody.find_all('tr')

            for row in rows:
                tds = row.find_all('td')

                # Compatibility matrix has 3 or 4 columns
                if len(tds) == 3 or len(tds) == 4:
                    splunk_version = tds[0].text.strip()

                    # Check if the version number found is valid
                    if splunk_version.count('.') != 2:
                        break

                    es_versions = tds[1].text.strip().replace('\n', ', ').split(', ')
                    itsi_versions = tds[2].text.strip().replace('\n', ', ').split(', ')

                    premium_app_compatibility[splunk_version] = {
                        'ES': [
                            es_version for es_version in es_versions
                            if es_version.count('.') == 2 and len(es_version) < 10
                        ],
                        'ITSI': [
                            itsi_version for itsi_version in itsi_versions
                            if itsi_version.count('.') == 2 and len(itsi_version) < 10
                        ]
                    }

                    if len(tds) == 4:
                        ite_work_versions = tds[3].text.strip().replace('\n', ', ').split(', ')
                        premium_app_compatibility[splunk_version]['ITE_work'] = [
                            ite_work_version for ite_work_version in  ite_work_versions
                            if ite_work_version.count('.') == 2 and len(ite_work_version) < 10
                        ]

        return premium_app_compatibility


    def check_premium_app_version(self, installed_app, premium_app_compatibility):
        installed_app['already_compatible'] = 'undecided'
        t_version = ''

        if self.target_version in premium_app_compatibility:
            if installed_app['title'] in ENTERPRISE_SECURITY_APPS:
                valid_versions = premium_app_compatibility[self.target_version]['ES']

            if installed_app['title'] in ITSI_APPS:
                valid_versions = premium_app_compatibility[self.target_version]['ITSI']

            valid_versions.sort(reverse=True)
            for valid_version in valid_versions:
                # In some cases the version in the compatibility matrix is abbriviated with .x
                # So we compare the part we actually have
                installed_app_version = installed_app['version'][0:len(valid_version)]
                if installed_app_version == valid_version:
                    installed_app['status'] = f"✅ App ready for {self.target_version}"
                    installed_app['already_compatible'] = 'yes'
                    t_version = valid_version
                    break

            # Check if there is a more recent version available
            if t_version and valid_versions.index(t_version) > 0:
                installed_app['status'] += f"\n    could be updated to {valid_versions[0]}"

        if not t_version:
            installed_app['status'] = f"🛑 Wasn't able to find version within compatibility matrix: {ES_ITSI_COMPAT_URL}\n" \
                                        f"please check manually."
        
        return installed_app


    def check_version(self, installed_app, splunkbase_apps, premium_app_compatibility):
        installed_app['status'] = ''
        installed_app['already_compatible'] = 'no'
        installed_app['is_premium_app'] = '0'
        installed_app['is_baseapp'] = '0'

        
        # Check if the app is an internal app or an app deployed by premium apps
        if installed_app['title'] in INTERNAL_APPS:
            installed_app['status'] = f"✅ App is an internal app so it will be updated during splunk upgrade."
            installed_app['already_compatible'] = 'yes'
            return installed_app

        is_baseapp = bool([base_app for base_app in BASE_APPS if installed_app['title'].endswith(base_app)])
        if is_baseapp:
            installed_app['is_baseapp'] = '1'
            if self.threat_baseapp_as_compatible:
                installed_app['status'] = f"✅ This is a baseapp."
                installed_app['already_compatible'] = 'yes'
                return installed_app

            installed_app['status'] = f"🛑 This is a baseapp."
            installed_app['already_compatible'] = 'no'
            return installed_app

        if 'version' not in installed_app or not installed_app['version']:
            installed_app['already_compatible'] = 'undecided'
            installed_app['status'] = '🛑 No version information available. Therefore were\'re not able to check for updates.'
            return installed_app

        if installed_app['title'] in ENTERPRISE_SECURITY_APPS or installed_app['title'] in ITSI_APPS:
            installed_app['is_premium_app'] = '1'
            return self.check_premium_app_version(installed_app, premium_app_compatibility)

        # On splunkbase all compatible versions are displayed as 9.0 not 9.0.1
        if self.target_version.count('.') > 1:
            target_version = '.'.join(self.target_version.split('.')[0:2])

        # Find splunkbase app
        splunkbase_app = None
        if 'title' in installed_app and installed_app['title']:
            splunkbase_app = [app for app in splunkbase_apps.values() if app['appid'] == installed_app['title']]

        if not splunkbase_app and 'label' in installed_app and installed_app['label']:
            splunkbase_app = [app for app in splunkbase_apps.values() if app['title'] == installed_app['label']]

        if not splunkbase_app:
            installed_app['already_compatible'] = 'undecided'
            installed_app['status'] = f"🛑 Wasn\'t able to find the app on splunkbase." + \
                                    f"\nIf you think that\'s a bug, open an issue on Github: {GITHUB_ISSUE_URL}"

            return installed_app

        if len(splunkbase_app) > 1:
            installed_app['already_compatible'] = 'undecided'
            installed_app['status'] = f"🛑 Found multiple apps on splunkbase. " + \
                                    f"\nThat\'s definitely  a bug, please open an issue on Github: {GITHUB_ISSUE_URL}"

            return installed_app

        splunkbase_app = splunkbase_app[0]

        # Let's split all available versions and filter out non suitable versions
        installed_version = [
            release for release in splunkbase_app['releases'] if
            release['title'] == installed_app['version'] and
            target_version in release['splunk_compatibility']
        ]
        lower_versions = [
            release for release in splunkbase_app['releases'] if
            version.parse(release['title']) < version.parse(installed_app['version']) and
            target_version in release['splunk_compatibility']
        ]
        higher_versions = [
            release for release in splunkbase_app['releases'] if
            version.parse(release['title']) > version.parse(installed_app['version']) and
            target_version in release['splunk_compatibility']
        ]

        # If the user need cloud compatibility we filter the apps further
        if self.cloud_compatibility_required:
            installed_version = [release for release in installed_version if
                                'Splunk Cloud' in release['product_compatibility']]
            lower_versions = [release for release in lower_versions if
                                'Splunk Cloud' in release['product_compatibility']]
            higher_versions = [release for release in higher_versions if
                                'Splunk Cloud' in release['product_compatibility']]

        # Check if the current version does already fit
        if installed_version:
            installed_app['status'] = f"✅ App ready for {target_version}"
            installed_app['already_compatible'] = 'yes'

            # Notify the user if he could update nevertheless
            if higher_versions:
                installed_app['status'] += f"\n    the most recent compatible version is {higher_versions[0]['title']} ({higher_versions[0]['path']})"

            return installed_app

        # In some cases the installed version is no longer available so we check the previous ones
        # Here we assume that if there is a older version that fits, the current version does as well (guess that's reasonable)
        if lower_versions:
            installed_app['status'] = f"✅ App ready for {target_version}"
            installed_app['already_compatible'] = 'yes'

            # Notify the user if he could update nevertheless
            if higher_versions:
                installed_app['status'] += f"\n    the most recent compatible version is {higher_versions[0]['title']} ({higher_versions[0]['path']})"

            return installed_app

        # Lets check newer versions
        if higher_versions:
            for higher_version in higher_versions[::-1]:
                installed_app['status'] = f"🛑 App should be updated to at least {higher_version['title']} ({higher_version['path']})"
                installed_app['already_compatible'] = 'no'

                # if the oldest compatible version is not this one there is a newer version
                # so lets provide the user the link for that one as well
                if higher_version['title'] != higher_versions[0]['title']:
                    installed_app['status'] += f"\n    the most recent compatible version is {higher_versions[0]['title']} ({higher_versions[0]['path']})"

                return installed_app

        installed_app['status'] = f"🛑 Wasn't able to find a suitable version for this app."
        installed_app['already_compatible'] = 'undecided'
        return installed_app



dispatch(CheckAppCompatibilityCommand, sys.argv, sys.stdin, sys.stdout, __name__)
