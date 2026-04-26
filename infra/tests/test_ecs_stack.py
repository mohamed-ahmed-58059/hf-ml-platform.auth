import aws_cdk as cdk
from aws_cdk.assertions import Template, Match
import unittest

from src.ecs_stack import EcsStack


class TestEcsStack(unittest.TestCase):
    def setUp(self):
        app = cdk.App()
        stack = EcsStack(
            app,
            "TestEcsStack",
            env=cdk.Environment(region="us-east-1"),
        )
        self.template = Template.from_stack(stack)

    # --- Security Groups ---

    def test_alb_sg_exists(self):
        self.template.has_resource_properties(
            "AWS::EC2::SecurityGroup",
            {
                "GroupName": "hf-ml-platform-auth-alb",
                "GroupDescription": "Port 8080 from rate limiter ECS tasks only",
            },
        )

    def test_alb_sg_allows_port_8080_from_rate_limiter_tasks_only(self):
        self.template.has_resource_properties(
            "AWS::EC2::SecurityGroupIngress",
            {
                "IpProtocol": "tcp",
                "FromPort": 8080,
                "ToPort": 8080,
                "SourceSecurityGroupId": Match.any_value(),
            },
        )

    def test_alb_sg_does_not_allow_cidr_ingress(self):
        sgs = self.template.find_resources(
            "AWS::EC2::SecurityGroup",
            {"Properties": {"GroupName": "hf-ml-platform-auth-alb"}},
        )
        for sg in sgs.values():
            for rule in sg["Properties"].get("SecurityGroupIngress", []):
                self.assertIsNone(
                    rule.get("CidrIp"),
                    "Auth ALB must not allow ingress from any CIDR — rate limiter task SG only",
                )

    def test_rate_limiter_task_sg_imported_from_ssm(self):
        self.template.has_parameter(
            "*",
            {"Type": "AWS::SSM::Parameter::Value<String>", "Default": "/hf-ml-platform/rate-limiter/task-sg-id"},
        )

    def test_auth_sg_exists(self):
        self.template.has_resource_properties(
            "AWS::EC2::SecurityGroup",
            {
                "GroupName": "hf-ml-platform-auth-tasks",
                "GroupDescription": "Allows inbound traffic on port 8080 from the auth ALB only",
            },
        )

    def test_auth_sg_allows_port_8080_from_alb_sg(self):
        self.template.has_resource_properties(
            "AWS::EC2::SecurityGroupIngress",
            {
                "IpProtocol": "tcp",
                "FromPort": 8080,
                "ToPort": 8080,
            },
        )

    def test_auth_sg_does_not_allow_all_inbound(self):
        sgs = self.template.find_resources(
            "AWS::EC2::SecurityGroup",
            {"Properties": {"GroupName": "hf-ml-platform-auth-tasks"}},
        )
        for sg in sgs.values():
            for rule in sg["Properties"].get("SecurityGroupIngress", []):
                self.assertNotEqual(rule.get("IpProtocol"), "-1")

    # --- IAM Roles ---

    def test_execution_role_assumed_by_ecs_tasks(self):
        self.template.has_resource_properties(
            "AWS::IAM::Role",
            {
                "RoleName": "hf-ml-platform-auth-execution",
                "AssumeRolePolicyDocument": Match.object_like({
                    "Statement": Match.array_with([
                        Match.object_like({
                            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        })
                    ])
                }),
            },
        )

    def test_execution_role_has_ecs_execution_policy(self):
        self.template.has_resource_properties(
            "AWS::IAM::Role",
            {
                "RoleName": "hf-ml-platform-auth-execution",
                "ManagedPolicyArns": Match.array_with([
                    Match.object_like({
                        "Fn::Join": Match.array_with([
                            Match.array_with([
                                "arn:",
                                ":iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
                            ])
                        ])
                    })
                ]),
            },
        )

    def test_execution_role_has_ssm_access(self):
        self.template.has_resource_properties(
            "AWS::IAM::Policy",
            {
                "PolicyDocument": Match.object_like({
                    "Statement": Match.array_with([
                        Match.object_like({
                            "Action": Match.array_with(["ssm:GetParameters"]),
                            "Effect": "Allow",
                        })
                    ])
                }),
            },
        )

    def test_execution_role_has_secrets_manager_access(self):
        self.template.has_resource_properties(
            "AWS::IAM::Policy",
            {
                "PolicyDocument": Match.object_like({
                    "Statement": Match.array_with([
                        Match.object_like({
                            "Action": Match.array_with(["secretsmanager:GetSecretValue"]),
                            "Effect": "Allow",
                        })
                    ])
                }),
            },
        )

    def test_task_role_assumed_by_ecs_tasks(self):
        self.template.has_resource_properties(
            "AWS::IAM::Role",
            {
                "RoleName": "hf-ml-platform-auth-task",
                "AssumeRolePolicyDocument": Match.object_like({
                    "Statement": Match.array_with([
                        Match.object_like({
                            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        })
                    ])
                }),
            },
        )

    def test_task_role_has_sns_publish(self):
        self.template.has_resource_properties(
            "AWS::IAM::Policy",
            {
                "PolicyDocument": Match.object_like({
                    "Statement": Match.array_with([
                        Match.object_like({
                            "Action": "sns:Publish",
                            "Effect": "Allow",
                        })
                    ])
                }),
            },
        )

    def test_task_role_has_no_sqs_access(self):
        policies = self.template.find_resources("AWS::IAM::Policy")
        for policy in policies.values():
            for stmt in policy["Properties"]["PolicyDocument"].get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                for action in actions:
                    self.assertFalse(
                        action.startswith("sqs:"),
                        f"Auth task role should not have SQS permissions, found: {action}",
                    )

    # --- Cluster ---

    def test_cluster_exists(self):
        self.template.has_resource_properties(
            "AWS::ECS::Cluster",
            {"ClusterName": "hf-ml-platform-auth"},
        )

    def test_cluster_has_fargate_capacity_providers(self):
        self.template.has_resource_properties(
            "AWS::ECS::ClusterCapacityProviderAssociations",
            {
                "CapacityProviders": Match.array_with(["FARGATE", "FARGATE_SPOT"]),
            },
        )

    # --- ALB ---

    def test_alb_is_internal(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            {
                "Name": "hf-ml-platform-auth",
                "Scheme": "internal",
            },
        )

    def test_alb_has_alb_sg_attached(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            {
                "Name": "hf-ml-platform-auth",
                "SecurityGroups": Match.array_with([
                    Match.object_like({
                        "Fn::GetAtt": [
                            Match.string_like_regexp("^AlbSg"),
                            "GroupId",
                        ]
                    })
                ]),
            },
        )

    def test_alb_is_in_private_subnets(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            {
                "Name": "hf-ml-platform-auth",
                "Subnets": Match.array_with([
                    {"Fn::ImportValue": "HfMlPlatformPrivateSubnetId1"},
                    {"Fn::ImportValue": "HfMlPlatformPrivateSubnetId2"},
                ]),
            },
        )

    # --- Target Group ---

    def test_target_group_exists(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"Name": "hf-ml-platform-auth"},
        )

    def test_target_group_port(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"Port": 8080},
        )

    def test_target_group_protocol(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"Protocol": "HTTP"},
        )

    def test_target_group_target_type(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"TargetType": "ip"},
        )

    def test_target_group_health_check_path(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"HealthCheckPath": "/health"},
        )

    def test_target_group_health_check_codes(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"Matcher": {"HttpCode": "200"}},
        )

    def test_target_group_health_check_interval(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"HealthCheckIntervalSeconds": 30},
        )

    def test_target_group_health_check_timeout(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"HealthCheckTimeoutSeconds": 5},
        )

    def test_target_group_healthy_threshold(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"HealthyThresholdCount": 2},
        )

    def test_target_group_unhealthy_threshold(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::TargetGroup",
            {"UnhealthyThresholdCount": 3},
        )

    # --- Listener ---

    def test_listener_exists(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::Listener",
            {"Port": 8080, "Protocol": "HTTP"},
        )

    def test_listener_forwards_to_target_group(self):
        self.template.has_resource_properties(
            "AWS::ElasticLoadBalancingV2::Listener",
            {
                "Port": 8080,
                "DefaultActions": Match.array_with([
                    Match.object_like({"Type": "forward"})
                ]),
            },
        )

    # --- Log Group ---

    def test_log_group_exists(self):
        self.template.has_resource_properties(
            "AWS::Logs::LogGroup",
            {"LogGroupName": "/hf-ml-platform/auth"},
        )

    def test_log_group_retention(self):
        self.template.has_resource_properties(
            "AWS::Logs::LogGroup",
            {"RetentionInDays": 7},
        )

    # --- Task Definition ---

    def test_task_definition_family(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {"Family": "hf-ml-platform-auth"},
        )

    def test_task_definition_cpu(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {"Cpu": "256"},
        )

    def test_task_definition_memory(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {"Memory": "512"},
        )

    def test_task_definition_uses_execution_role(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ExecutionRoleArn": Match.object_like({
                    "Fn::GetAtt": [
                        Match.string_like_regexp("^ExecutionRole"),
                        "Arn",
                    ]
                })
            },
        )

    def test_task_definition_uses_task_role(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "TaskRoleArn": Match.object_like({
                    "Fn::GetAtt": [
                        Match.string_like_regexp("^TaskRole"),
                        "Arn",
                    ]
                })
            },
        )

    # --- Container ---

    def test_container_name(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ContainerDefinitions": Match.array_with([
                    Match.object_like({"Name": "auth"})
                ])
            },
        )

    def test_container_port(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ContainerDefinitions": Match.array_with([
                    Match.object_like({
                        "PortMappings": Match.array_with([
                            Match.object_like({"ContainerPort": 8080})
                        ])
                    })
                ])
            },
        )

    def test_container_uses_awslogs_driver(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ContainerDefinitions": Match.array_with([
                    Match.object_like({
                        "LogConfiguration": Match.object_like({
                            "LogDriver": "awslogs"
                        })
                    })
                ])
            },
        )

    def test_container_environment_port(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ContainerDefinitions": Match.array_with([
                    Match.object_like({
                        "Environment": Match.array_with([
                            Match.object_like({"Name": "PORT", "Value": "8080"})
                        ])
                    })
                ])
            },
        )

    def test_container_environment_spring_profile(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ContainerDefinitions": Match.array_with([
                    Match.object_like({
                        "Environment": Match.array_with([
                            Match.object_like({
                                "Name": "SPRING_PROFILES_ACTIVE",
                                "Value": "production",
                            })
                        ])
                    })
                ])
            },
        )

    def test_container_postgres_host_from_ssm(self):
        self.template.has_parameter(
            "*",
            {"Type": "AWS::SSM::Parameter::Value<String>", "Default": "/hf-ml-platform/rds/endpoint"},
        )

    def test_container_db_access_sg_from_ssm(self):
        self.template.has_parameter(
            "*",
            {"Type": "AWS::SSM::Parameter::Value<String>", "Default": "/hf-ml-platform/rds/db-access-sg-id"},
        )

    def test_container_postgres_user_from_secrets_manager(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ContainerDefinitions": Match.array_with([
                    Match.object_like({
                        "Secrets": Match.array_with([
                            Match.object_like({"Name": "POSTGRES_USER"})
                        ])
                    })
                ])
            },
        )

    def test_container_postgres_password_from_secrets_manager(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ContainerDefinitions": Match.array_with([
                    Match.object_like({
                        "Secrets": Match.array_with([
                            Match.object_like({"Name": "POSTGRES_PASSWORD"})
                        ])
                    })
                ])
            },
        )

    def test_container_rsa_private_key_from_secrets_manager(self):
        self.template.has_resource_properties(
            "AWS::ECS::TaskDefinition",
            {
                "ContainerDefinitions": Match.array_with([
                    Match.object_like({
                        "Secrets": Match.array_with([
                            Match.object_like({"Name": "RSA_PRIVATE_KEY"})
                        ])
                    })
                ])
            },
        )

    def test_container_does_not_have_redis_env_vars(self):
        task_defs = self.template.find_resources("AWS::ECS::TaskDefinition")
        for td in task_defs.values():
            for container in td["Properties"].get("ContainerDefinitions", []):
                for env in container.get("Environment", []):
                    self.assertNotIn(
                        "REDIS",
                        env.get("Name", ""),
                        "Auth service should not have Redis env vars",
                    )

    # --- Service ---

    def test_service_exists(self):
        self.template.has_resource_properties(
            "AWS::ECS::Service",
            {"ServiceName": "hf-ml-platform-auth"},
        )

    def test_service_desired_count(self):
        self.template.has_resource_properties(
            "AWS::ECS::Service",
            {"DesiredCount": 1},
        )

    def test_service_launch_type(self):
        self.template.has_resource_properties(
            "AWS::ECS::Service",
            {"LaunchType": "FARGATE"},
        )

    def test_service_in_private_subnets(self):
        self.template.has_resource_properties(
            "AWS::ECS::Service",
            {
                "NetworkConfiguration": Match.object_like({
                    "AwsvpcConfiguration": Match.object_like({
                        "Subnets": Match.array_with([
                            {"Fn::ImportValue": "HfMlPlatformPrivateSubnetId1"},
                            {"Fn::ImportValue": "HfMlPlatformPrivateSubnetId2"},
                        ]),
                        "AssignPublicIp": "DISABLED",
                    })
                })
            },
        )

    def test_service_registered_with_target_group(self):
        self.template.has_resource_properties(
            "AWS::ECS::Service",
            {
                "LoadBalancers": Match.array_with([
                    Match.object_like({"ContainerPort": 8080})
                ])
            },
        )

    # --- SSM Output ---

    def test_auth_url_ssm_parameter_exists(self):
        self.template.has_resource_properties(
            "AWS::SSM::Parameter",
            {"Name": "/hf-ml-platform/auth/url"},
        )

    def test_alb_dns_cfn_output_exists(self):
        self.template.has_output(
            "AlbDns",
            {"Export": {"Name": "HfMlPlatformAuthAlbDns"}},
        )
