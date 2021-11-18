import json
import time
from datetime import datetime, timedelta

import boto3
import cachetools

from .base import LambdaBase
from .signer import Signer


def get_secret(arn, logger) -> str:
    region_name = "us-east-1"

    logger.warning("attempting to get secret %s", arn)

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name="secretsmanager", region_name=region_name
    )

    get_secret_value_response = client.get_secret_value(SecretId=arn)

    # Decrypts secret using the associated KMS CMK.
    # Depending on whether the secret is a string or binary, one of these fields will be populated.
    if "SecretString" in get_secret_value_response:
        secret = get_secret_value_response["SecretString"]
        logger.warning("secret string %s", repr(secret)[0:50])
        return json.loads(secret)


class ViewerRequest(LambdaBase):
    COOKIE_PREFIX = "/_/cookie"

    def __init__(self, conf_file="lambda_config.json"):
        super().__init__("viewer-request", conf_file)
        self._db_client = None
        self._cache = cachetools.TTLCache(
            maxsize=1,
            ttl=timedelta(
                minutes=self.conf.get("config_cache_ttl", 2)
            ).total_seconds(),
            timer=time.monotonic,
        )

    @property
    def secret(self):
        out = self._cache.get("secret")
        if out is None:
            secret_arn = self.conf.get("secret")
            out = get_secret(secret_arn, self.logger)
            self._cache["secret"] = out
        return out

    @property
    def cookie_key(self):
        return self.secret["cookie_key"]

    def handler(self, event, context):
        # pylint: disable=unused-argument
        request = event["Records"][0]["cf"]["request"]
        uri = request["uri"]

        if not request["uri"].startswith(self.COOKIE_PREFIX + "/"):
            # nothing to be done
            return request

        redir_uri = uri[len(self.COOKIE_PREFIX) :]

        signer = Signer(self.cookie_key, self.conf.get("key_id"))

        expire = timedelta(minutes=30)
        common_attrs = f"Secure; Max-Age={int(expire.total_seconds())}"

        cookies_content = signer.cookies_for_policy(
            resource="/content/*",
            date_less_than=datetime.utcnow() + expire,
        )
        cookies_origin = signer.cookies_for_policy(
            resource="/origin/*",
            date_less_than=datetime.utcnow() + expire,
        )

        out = {
            "status": "302",
            "headers": {
                "location": [
                    {"value": redir_uri},
                ],
                "cache-control": [
                    {"value": "no-store"},
                ],
                "set-cookie": [
                    {"value": "Cookie-From-Headers=Foo-Bar"},
                ],
            },
            "cookies": {
                "CloudFront-Key-Pair-Id": {
                    "value": cookies_content["CloudFront-Key-Pair-Id"],
                    "attributes": common_attrs,
                },
                "CloudFront-Policy": {
                    "multiValue": [
                        {
                            "value": cookies["CloudFront-Policy"],
                            "attributes": f"{common_attrs}; Path={path}",
                        }
                        for (cookies, path) in [
                            (cookies_content, "/content/"),
                            (cookies_origin, "/origin/"),
                        ]
                    ]
                },
                "CloudFront-Signature": {
                    "multiValue": [
                        {
                            "value": cookies["CloudFront-Signature"],
                            "attributes": f"{common_attrs}; Path={path}",
                        }
                        for (cookies, path) in [
                            (cookies_content, "/content/"),
                            (cookies_origin, "/origin/"),
                        ]
                    ]
                },
            },
        }

        # for debugging only
        body = json.dumps(out, indent=4)
        out["body"] = body

        return out


# Make handler available at module level
lambda_handler = ViewerRequest().handler  # pylint: disable=invalid-name
