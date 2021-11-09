import argparse
import csv
import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path

import boto3


def try_int(value):
    try:
        return int(value)
    except BaseException:
        return 0


AWS_DEFAULT_DURATION = try_int(os.environ.get('AWS_DEFAULT_DURATION')) or 3200


class InventoryInstances:

    arguments = None
    log = logging.getLogger('inventory_instances')
    extra_params = None

    def __init__(self):
        handler = logging.StreamHandler(sys.stdout)
        self.log.addHandler(handler)
        parser = argparse.ArgumentParser()
        parser.add_argument('--region', '-r', action='append', type=str, dest='regions', help='List of regions to be used, can be used multiple times.')
        parser.add_argument('--instance-id', '-i', action='append', type=str, dest='instance_ids', help='List of instance ids, can be used multiple times.')
        parser.add_argument('--filter', '-f', action='append', metavar="KEY=VALUE", nargs='+', dest='filters', help="""List of filters to use, example:
        network-interface.addresses.association.public-ip 1.1.1.1 or
        network-interface.addresses.private-ip-address 192.168.1.1, check boto3
        documentation:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
        """)
        parser.add_argument('--output', '-o', dest='output_file', type=Path, required=False, help="""
            Where do you want the file, by default it will be written to stdout.
            If provided, only json, csv and tsv extensions are valid.
        """)
        self.args = parser.parse_args()
        _pre_filters = {}
        self.args.filters = self.args.filters or {}
        for name, value in self.args.filters:
            _pre_filters.setdefault(name, [])
            _pre_filters[name].append(value)
            _pre_filters[name] = list(set(_pre_filters[name]))
        _pre_filters = dict(_pre_filters)
        filters = [
            {
                'Name': name,
                'Values': values
            } for name, values in _pre_filters.items()
        ]
        self.extra_params = {}

        if self.args.instance_ids:
            self.extra_params['InstanceIds'] = self.args.instance_ids

        if filters:
            self.extra_params = {
                'Filters': filters
            }

    def describe_instances(self, region_name):

        ec2 = boto3.client('ec2', region_name=region_name)

        self.extra_params = self.extra_params or {}
        NextToken = None
        reservations = []

        try:
            response = ec2.describe_instances(**self.extra_params)
            NextToken = response.get('NextToken')
        except BaseException:
            pass # fail silently

        while NextToken:
            self.extra_params['NextToken'] = NextToken
            try:
                response = ec2.describe_instances(**self.extra_params)
                NextToken = response.get('NextToken')
                reservations.extend(response.get('Reservations'))
            except BaseException:
                # fail silently
                pass
        return reservations

    def get_opted_regions(self):
        ec2 = boto3.client('ec2', os.environ.get('AWS_DEFAULT_REGION'))
        all_regions = ec2.describe_regions(AllRegions=True)
        regions = []
        for region in all_regions.get('Regions', []):
            if region['OptInStatus'] not in ['opt-in-not-required', 'opted-in']:
                continue
            regions.append(region['RegionName'])
        return regions


    def get_all_instances(self):
        regions = self.args.regions or self.get_opted_regions()
        instances = {}
        for region_name in regions:
            self.log.debug(f'Getting all instances for region {region_name}')
            instances[region_name] = self.describe_instances(region_name)
            self.log.debug(f'END Getting all instances for region {region_name}')
        return instances

    def export_as_csv(self, file_name, exportable_data, ip_types=None):
        ip_types = ip_types or {}
        headers = ['InstanceId', 'HostId', 'Region', 'AvailabilityZone']

        for ip_type, quantity in ip_types.items():
            if not quantity:
                continue

            for num in range(1, quantity + 1):
                headers.append(f'{ip_type} {num}')

        writer = csv.DictWriter(open(file_name), fieldnames=headers)
        writer.writeheader()
        writer.writerows(exportable_data)




    def check_invent(self):
        total_public_ip_number = 0
        total_private_ip_number = 0
        total_ipv6_number = 0
        total_carrier_ip_number = 0
        exportable_data = {}
        all_instances = self.get_all_instances()
        for region_name, instances in all_instances.items():
            for instance in instances:
                public_ips = set()
                private_ips = set()
                ipv6_ips = set()
                carrier_ips = set()
                inst = {
                    'InstanceId': instance['InstanceId'],
                    'HostId': instance['Placement'].get('HostId'),
                    'Region': region_name,
                    'AvailabilityZone': instance['Placement']['AvailabilityZone'],
                }

                for interface in instance.get('NetworkInterfaces', []):
                    assoc = interface.get('Association') or {}
                    public_ip = assoc.get('PublicIp')
                    carrier_ip = assoc.get('CarrierIp')
                    if carrier_ip:
                        carrier_ips.add(carrier_ip)
                    if public_ip:
                        public_ips.add(public_ip)

                    for ipv6_address in interface.get('Ipv6Addresses', []):
                        ipv6_ips.add(ipv6_address.get('Ipv6Address'))


                    for private_ip in interface.get('PrivateIpAddresses', []):
                        assoc = private_ip.get('Association') or {}
                        public_ip = assoc.get('PublicIp')
                        if public_ip:
                            public_ips.add(public_ip)
                        private_ips.add(private_ip['PrivateIpAddress'])

                for num, ip in enumerate(public_ips, 1):
                    inst[f'Public IP {num}'] = ip

                for num, ip in enumerate(private_ips, 1):
                    inst[f'Private IP {num}'] = ip

                for num, ip in enumerate(carrier_ips, 1):
                    inst[f'Carrier IP {num}'] = ip

                for num, ip in enumerate(ipv6_ips, 1):
                    inst[f'IPv6 {num}'] = ip

                exportable_data.append(inst)
                total_public_ip_number = max(total_public_ip_number, len(public_ips))
                total_private_ip_number = max(total_private_ip_number, len(private_ips))
                total_ipv6_number = max(total_ipv6_number, len(ipv6_ips))
                total_carrier_ip_number = max(total_carrier_ip_number, len(carrier_ips))

        if not self.args.output_file:
            self.log.info(json.dumps(exportable_data, indent=4))
            return

        file_name = str(self.args.output_file.expanduser().resolve())

        if file_name.endswith('.json'):
            with open(file_name, 'w') as json_file:
                return json_file.write(json.dumps(intent=4))

        if file_name.endswith('.tsv'):
            with open(file_name, 'w') as json_file:
                return self.export_as_csv(file_name,
                           exportable_data,
                           delimiter="\t",
                           ip_types={
                               'Public IP': total_public_ip_number,
                               'Private IP': total_private_ip_number,
                               'Carrier IP': total_carrier_ip_number,
                               'IPv6': total_ipv6_number,

                           })

        if file_name.endswith('.csv'):
            with open(file_name, 'w') as json_file:
                return self.export_as_csv(file_name,
                           exportable_data,
                           delimiter=',',
                           ip_types={
                               'Public IP': total_public_ip_number,
                               'Private IP': total_private_ip_number,
                               'Carrier IP': total_carrier_ip_number,
                               'IPv6': total_ipv6_number,

                           })
        exit('Output can only be csv or json.')



if __name__ == '__main__':
    inventory = InventoryInstances()
    inventory.check_invent()
