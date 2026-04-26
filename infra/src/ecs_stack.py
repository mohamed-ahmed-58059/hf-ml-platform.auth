import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_ecr as ecr
import aws_cdk.aws_ecs as ecs
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_logs as logs
import aws_cdk.aws_secretsmanager as secretsmanager
import aws_cdk.aws_ssm as ssm
from constructs import Construct


class EcsStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        repository = ecr.Repository.from_repository_name(
            self,
            "AuthRepo",
            "hf-ml-platform/auth",
        )

        vpc = ec2.Vpc.from_vpc_attributes(
            self,
            "ImportedVpc",
            vpc_id=cdk.Fn.import_value("HfMlPlatformVpcId"),
            availability_zones=["us-east-1a", "us-east-1b"],
            public_subnet_ids=[
                cdk.Fn.import_value("HfMlPlatformPublicSubnetId1"),
                cdk.Fn.import_value("HfMlPlatformPublicSubnetId2"),
            ],
            private_subnet_ids=[
                cdk.Fn.import_value("HfMlPlatformPrivateSubnetId1"),
                cdk.Fn.import_value("HfMlPlatformPrivateSubnetId2"),
            ],
        )

        sg_alb = ec2.SecurityGroup(
            self,
            "AlbSg",
            vpc=vpc,
            security_group_name="hf-ml-platform-auth-alb",
            description="Port 8080 from rate limiter ECS tasks only",
        )

        sg_rate_limiter_tasks = ec2.SecurityGroup.from_security_group_id(
            self,
            "RateLimiterTaskSg",
            ssm.StringParameter.value_for_string_parameter(
                self, "/hf-ml-platform/rate-limiter/task-sg-id"
            ),
        )

        sg_alb.add_ingress_rule(
            peer=sg_rate_limiter_tasks,
            connection=ec2.Port.tcp(8080),
            description="Forwarded traffic from rate limiter ECS tasks",
        )

        sg_auth = ec2.SecurityGroup(
            self,
            "AuthSg",
            vpc=vpc,
            security_group_name="hf-ml-platform-auth-tasks",
            description="Allows inbound traffic on port 8080 from the auth ALB only",
        )

        sg_auth.add_ingress_rule(
            peer=sg_alb,
            connection=ec2.Port.tcp(8080),
            description="Allow traffic from auth ALB",
        )

        execution_role = iam.Role(
            self,
            "ExecutionRole",
            role_name="hf-ml-platform-auth-execution",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                ),
            ],
        )

        execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ssm:GetParameters",
                    "secretsmanager:GetSecretValue",
                ],
                resources=[
                    f"arn:aws:ssm:us-east-1:{self.account}:parameter/hf-ml-platform/*",
                    f"arn:aws:secretsmanager:us-east-1:{self.account}:secret:hf-ml-platform/*",
                ],
            )
        )

        task_role = iam.Role(
            self,
            "TaskRole",
            role_name="hf-ml-platform-auth-task",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
        )

        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["sns:Publish"],
                resources=[
                    f"arn:aws:sns:us-east-1:{self.account}:hf-ml-platform-cache-invalidation"
                ],
            )
        )

        self.cluster = ecs.Cluster(
            self,
            "Cluster",
            cluster_name="hf-ml-platform-auth",
            vpc=vpc,
            enable_fargate_capacity_providers=True,
        )

        self.target_group = elbv2.ApplicationTargetGroup(
            self,
            "TargetGroup",
            target_group_name="hf-ml-platform-auth",
            vpc=vpc,
            port=8080,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(
                path="/health",
                healthy_http_codes="200",
                interval=cdk.Duration.seconds(30),
                timeout=cdk.Duration.seconds(5),
                healthy_threshold_count=2,
                unhealthy_threshold_count=3,
            ),
        )

        self.alb = elbv2.ApplicationLoadBalancer(
            self,
            "Alb",
            load_balancer_name="hf-ml-platform-auth",
            vpc=vpc,
            internet_facing=False,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_group=sg_alb,
        )

        self.alb.add_listener(
            "Listener",
            port=8080,
            protocol=elbv2.ApplicationProtocol.HTTP,
            default_target_groups=[self.target_group],
            open=False,
        )

        log_group = logs.LogGroup(
            self,
            "LogGroup",
            log_group_name="/hf-ml-platform/auth",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        self.task_definition = ecs.FargateTaskDefinition(
            self,
            "TaskDefinition",
            family="hf-ml-platform-auth",
            cpu=256,
            memory_limit_mib=512,
            execution_role=execution_role,
            task_role=task_role,
        )

        db_secret = secretsmanager.Secret.from_secret_name_v2(
            self,
            "DbSecret",
            "hf-ml-platform/rds",
        )

        rsa_private_key = secretsmanager.Secret.from_secret_name_v2(
            self,
            "RsaPrivateKey",
            "hf-ml-platform/auth/rsa-private-key",
        )

        image_tag = self.node.try_get_context("image_tag") or "latest"

        self.task_definition.add_container(
            "AuthContainer",
            container_name="auth",
            image=ecs.ContainerImage.from_ecr_repository(repository, tag=image_tag),
            port_mappings=[ecs.PortMapping(container_port=8080)],
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="auth",
                log_group=log_group,
            ),
            environment={
                "PORT": "8080",
                "SPRING_PROFILES_ACTIVE": "production",
                "POSTGRES_HOST": ssm.StringParameter.value_for_string_parameter(
                    self, "/hf-ml-platform/rds/endpoint"
                ),
                "POSTGRES_DB": "hf_platform",
                "SNS_TOPIC_ARN": f"arn:aws:sns:us-east-1:{self.account}:hf-ml-platform-cache-invalidation",
            },
            secrets={
                "POSTGRES_USER": ecs.Secret.from_secrets_manager(db_secret, "username"),
                "POSTGRES_PASSWORD": ecs.Secret.from_secrets_manager(db_secret, "password"),
                "RSA_PRIVATE_KEY": ecs.Secret.from_secrets_manager(rsa_private_key),
            },
        )

        sg_db_access = ec2.SecurityGroup.from_security_group_id(
            self,
            "DbAccessSg",
            ssm.StringParameter.value_for_string_parameter(
                self, "/hf-ml-platform/rds/db-access-sg-id"
            ),
        )

        private_subnet_1 = ec2.Subnet.from_subnet_id(
            self, "PrivateSubnet1", cdk.Fn.import_value("HfMlPlatformPrivateSubnetId1")
        )
        private_subnet_2 = ec2.Subnet.from_subnet_id(
            self, "PrivateSubnet2", cdk.Fn.import_value("HfMlPlatformPrivateSubnetId2")
        )

        self.service = ecs.FargateService(
            self,
            "Service",
            service_name="hf-ml-platform-auth",
            cluster=self.cluster,
            task_definition=self.task_definition,
            desired_count=1,
            vpc_subnets=ec2.SubnetSelection(subnets=[private_subnet_1, private_subnet_2]),
            security_groups=[sg_auth, sg_db_access],
            assign_public_ip=False,
        )

        self.service.attach_to_application_target_group(self.target_group)

        ssm.StringParameter(
            self,
            "AuthUrlParam",
            parameter_name="/hf-ml-platform/auth/url",
            string_value=f"http://{self.alb.load_balancer_dns_name}:8080",
        )

        cdk.CfnOutput(
            self,
            "AlbDns",
            value=self.alb.load_balancer_dns_name,
            export_name="HfMlPlatformAuthAlbDns",
        )
