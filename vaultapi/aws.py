import logging
import os
from typing import List

LOGGER = logging.getLogger(__name__)


class AWSClient:
    """AWS client object to retrieve parameters (parameter store) or secrets (from secrets manager).

    >>> AWSClient

    """

    def __init__(self):
        """Instantiates the client object."""
        try:
            # noinspection PyPackageRequirements,PyUnresolvedReferences
            import boto3
        except ModuleNotFoundError:
            raise EnvironmentError(
                "Module not found: boto3 - Run 'pip install VaultAPI-Client[aws]'"
            )

        session = boto3.Session(
            profile_name=os.environ.get("AWS_PROFILE_NAME"),
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            region_name=os.environ.get("AWS_DEFAULT_REGION"),
        )
        self.secret_client = session.client(service_name="secretsmanager")
        self.ssm_client = session.client(service_name="ssm")

    def get_aws_secrets(self, name: str = None) -> str | List[str] | None:
        """Get secrets from AWS secretsmanager.

        Args:
            name: Get name of the particular secret.

        Returns:
            str | List[str]:
            Returns the value of the secret or list of all secrets' names.
        """
        if name:
            LOGGER.info("Retrieving the secret '%s' from AWS secrets manager", name)
            try:
                response = self.secret_client.get_secret_value(SecretId=name)
            except Exception as error:
                LOGGER.exception(error)
                return None
            return response["SecretString"]
        paginator = self.secret_client.get_paginator("list_secrets")
        page_results = paginator.paginate().build_full_result()
        return [page["Name"] for page in page_results["SecretList"]]

    def get_aws_params(self, name: str = None) -> str | List[str] | None:
        """Get SSM parameters from AWS.

        Args:
            name: Get name of the particular parameter.

        Returns:
            str | List[str]:
            Returns the value of the parameter or list of all parameter names.
        """
        if name:
            LOGGER.info("Retrieving the parameter '%s' from AWS parameter store", name)
            try:
                response = self.ssm_client.get_parameter(Name=name, WithDecryption=True)
            except Exception as error:
                LOGGER.exception(error)
                return None
            return response["Parameter"]["Value"]
        paginator = self.ssm_client.get_paginator("describe_parameters")
        page_results = paginator.paginate().build_full_result()
        return [page["Name"] for page in page_results["Parameters"]]
