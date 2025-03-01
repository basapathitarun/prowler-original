from boto3 import client, resource
from moto import mock_ec2, mock_elbv2, mock_wafv2

from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_WAFv2_Service:
    # Test WAFv2 Service
    @mock_wafv2
    def test_service(self):
        # WAFv2 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(audit_info)
        assert wafv2.service == "wafv2"

    # Test WAFv2 Client
    @mock_wafv2
    def test_client(self):
        # WAFv2 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(audit_info)
        for regional_client in wafv2.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAFV2"

    # Test WAFv2 Session
    @mock_wafv2
    def test__get_session__(self):
        # WAFv2 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(audit_info)
        assert wafv2.session.__class__.__name__ == "Session"

    # Test WAFv2 Describe Web ACLs
    @mock_wafv2
    def test__list_web_acls__(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        # WAFv2 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(audit_info)
        assert len(wafv2.web_acls) == 1
        assert wafv2.web_acls[0].name == waf["Name"]
        assert wafv2.web_acls[0].region == AWS_REGION_EU_WEST_1
        assert wafv2.web_acls[0].arn == waf["ARN"]
        assert wafv2.web_acls[0].id == waf["Id"]

    # Test WAFv2 Describe Web ACLs Resources
    @mock_ec2
    @mock_elbv2
    @mock_wafv2
    def test__list_resources_for_web_acl__(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}a",
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}b",
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        wafv2.associate_web_acl(WebACLArn=waf["ARN"], ResourceArn=lb["LoadBalancerArn"])
        # WAFv2 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(audit_info)
        wafv2.web_acls[0].albs.append(lb["LoadBalancerArn"])
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[0].albs) == 1
        assert lb["LoadBalancerArn"] in wafv2.web_acls[0].albs
