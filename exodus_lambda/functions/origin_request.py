import base64
import json
import time
import urllib
from datetime import datetime, timedelta, timezone

import boto3
import cachetools
from botocore.exceptions import ClientError

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


class OriginRequest(LambdaBase):
    def __init__(self, conf_file="lambda_config.json"):
        super().__init__("origin-request", conf_file)
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

    @property
    def definitions(self):
        out = self._cache.get("exodus-config")
        if out is None:
            table = self.conf["config_table"]["name"]

            query_result = self.db_client.query(
                TableName=table,
                Limit=1,
                ScanIndexForward=False,
                KeyConditionExpression="config_id = :id and from_date <= :d",
                ExpressionAttributeValues={
                    ":id": {"S": "exodus-config"},
                    ":d": {
                        "S": str(
                            datetime.now(timezone.utc).isoformat(
                                timespec="milliseconds"
                            )
                        )
                    },
                },
            )
            if query_result["Items"]:
                item = query_result["Items"][0]
                out = json.loads(item["config"]["S"])
            else:
                self.logger.warning(
                    "No 'exodus-config' available in table %s", table
                )
                out = {}

            self._cache["exodus-config"] = out

        return out

    @property
    def db_client(self):
        if not self._db_client:
            self._db_client = boto3.client("dynamodb", region_name=self.region)

        return self._db_client

    def uri_alias(self, uri, aliases):
        # Resolve every alias between paths within the uri (e.g.
        # allow RHUI paths to be aliased to non-RHUI).
        #
        # Aliases are expected to come from cdn-definitions.

        remaining = aliases

        # We do multiple passes here to ensure that nested aliases
        # are resolved correctly, regardless of the order in which
        # they're provided.
        while remaining:
            processed = []

            for alias in remaining:
                if uri.startswith(alias["src"] + "/") or uri == alias["src"]:
                    uri = uri.replace(alias["src"], alias["dest"], 1)
                    processed.append(alias)

            if not processed:
                # We didn't resolve any alias, then we're done processing.
                break

            # We resolved at least one alias, so we need another round
            # in case others apply now. But take out anything we've already
            # processed, so it is not possible to recurse.
            remaining = [r for r in remaining if r not in processed]

        return uri

    def resolve_aliases(self, uri):
        # aliases relating to origin, e.g. content/origin <=> origin
        uri = self.uri_alias(uri, self.definitions.get("origin_alias") or [])

        # aliases relating to rhui; listing files are a special exemption
        # because they must be allowed to differ for rhui vs non-rhui.
        if not uri.endswith("/listing"):
            uri = self.uri_alias(uri, self.definitions.get("rhui_alias") or [])

        return uri

    def handler(self, event, context):
        # pylint: disable=unused-argument

        request = event["Records"][0]["cf"]["request"]

        if "/_meta" in request["uri"]:
            return self.meta_handler(request)

        return self.content_handler(request)

    def meta_handler(self, request):
        uri = request["uri"]

        if not uri.startswith("/_meta/cookie"):
            return {"status": "404"}

        redir_uri = uri[len("/_meta/cookie") :]

        signer = Signer(self.cookie_key, self.conf.get("key_id"))

        expire = timedelta(minutes=30)

        cookies_content = signer.cookies_for_policy(
            append=f"; Secure; Path=/content/; Max-Age={int(expire.total_seconds())}",
            resource="/content/*",
            date_less_than=datetime.utcnow() + expire,
        )
        cookies_origin = signer.cookies_for_policy(
            append=f"; Secure; Path=/origin/; Max-Age={int(expire.total_seconds())}",
            resource="/origin/*",
            date_less_than=datetime.utcnow() + expire,
        )

        out = {
            "status": "302",
            "headers": {
                "Location": [redir_uri],
                "Set-Cookie": cookies_content + cookies_origin,
            },
        }

        # for debugging only
        body = json.dumps(out, indent=4)
        out["body"] = body

        return out

    def content_handler(self, request):
        uri = self.resolve_aliases(request["uri"])
        self.logger.info(
            "The request value for origin_request beginning is '%s'",
            json.dumps(request, indent=4, sort_keys=True),
        )
        self.logger.info(
            "The uri value for origin_request beginning is '%s'", uri
        )
        table = self.conf["table"]["name"]

        self.logger.info("Querying '%s' table for '%s'...", table, uri)

        query_result = self.db_client.query(
            TableName=table,
            Limit=1,
            ScanIndexForward=False,
            KeyConditionExpression="web_uri = :u and from_date <= :d",
            ExpressionAttributeValues={
                ":u": {"S": uri},
                ":d": {
                    "S": str(
                        datetime.now(timezone.utc).isoformat(
                            timespec="milliseconds"
                        )
                    )
                },
            },
        )

        if query_result["Items"]:
            self.logger.info("Item found for '%s'", uri)

            try:
                # Add custom header containing the original request uri
                request["headers"]["exodus-original-uri"] = [
                    {"key": "exodus-original-uri", "value": request["uri"]}
                ]

                # Update request uri to point to S3 object key
                request["uri"] = (
                    "/" + query_result["Items"][0]["object_key"]["S"]
                )
                content_type = query_result["Items"][0]["content_type"]["S"]
                if content_type:
                    request["querystring"] = urllib.parse.urlencode(
                        {"response-content-type": content_type}
                    )

                self.logger.info(
                    "The request value for origin_request end is '%s'",
                    json.dumps(request, indent=4, sort_keys=True),
                )

                return request
            except Exception as err:
                self.logger.exception(
                    "Exception occurred while processing %s",
                    json.dumps(query_result["Items"][0]),
                )

                raise err
        else:
            self.logger.info("No item found for '%s'", uri)

            # Report 404 to prevent attempts on S3
            return {"status": "404", "statusDescription": "Not Found"}


# Make handler available at module level
lambda_handler = OriginRequest().handler  # pylint: disable=invalid-name
