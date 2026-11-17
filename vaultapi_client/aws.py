import os
import warnings
from typing import List


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
            profile_name=os.environ.get("AWS_PROFILE_NAME", ""),
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", ""),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
            region_name=os.environ.get("AWS_DEFAULT_REGION", ""),
        )
        self.secret_client = session.client(service_name="secretsmanager")
        self.ssm_client = session.client(service_name="ssm")

    def get_aws_secrets(self, name: str) -> str | List[str] | None:
        """Get secrets from AWS secretsmanager.

        Args:
            name: Name of the secret.

        Returns:
            str | List[str]:
            Returns the value of the secret or list of all secrets' names.
        """
        try:
            response = self.secret_client.get_secret_value(SecretId=name)
        except Exception as error:
            warnings.warn(error.__str__(), category=UserWarning, stacklevel=3)
            return None
        return response["SecretString"]

    def get_aws_params(self, name: str) -> str | List[str] | None:
        """Get SSM parameters from AWS.

        Args:
            name: Name of the parameter.

        Returns:
            str | List[str]:
            Returns the value of the parameter or list of all parameter names.
        """
        try:
            response = self.ssm_client.get_parameter(Name=name, WithDecryption=True)
        except Exception as error:
            warnings.warn(error.__str__(), category=UserWarning, stacklevel=3)
            return None
        return response["Parameter"]["Value"]
