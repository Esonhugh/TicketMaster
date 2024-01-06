from keystone.common import utils as ks_utils
from oslo_utils import timeutils
import uuid
import datetime
import base64

class BasePayload(object):
    # each payload variant should have a unique version
    version = None
    default_method_list = ['external', 'password', 'token', 'oauth1', 'mapped',
                         'application_credential']
     
    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        """Assemble the payload of a token.

        :param user_id: identifier of the user in the token request
        :param methods: list of authentication methods used
        :param system: a string including system scope information
        :param project_id: ID of the project to scope to
        :param domain_id: ID of the domain to scope to
        :param expires_at: datetime of the token's expiration
        :param audit_ids: list of the token's audit IDs
        :param trust_id: ID of the trust in effect
        :param federated_group_ids: list of group IDs from SAML assertion
        :param identity_provider_id: ID of the user's identity provider
        :param protocol_id: federated protocol used for authentication
        :param access_token_id: ID of the secret in OAuth1 authentication
        :param app_cred_id: ID of the application credential in effect
        :param thumbprint: thumbprint of the certificate in OAuth2 mTLS
        :returns: the payload of a token

        """
        raise NotImplementedError()

    @classmethod
    def disassemble(cls, payload):
        """Disassemble an unscoped payload into the component data.

        The tuple consists of::

            (user_id, methods, system, project_id, domain_id,
             expires_at_str, audit_ids, trust_id, federated_group_ids,
             identity_provider_id, protocol_id,` access_token_id, app_cred_id)

        * ``methods`` are the auth methods.

        Fields will be set to None if they didn't apply to this payload type.

        :param payload: this variant of payload
        :returns: a tuple of the payloads component data

        """
        raise NotImplementedError()

    @classmethod
    def convert_uuid_hex_to_bytes(cls, uuid_string):
        """Compress UUID formatted strings to bytes.

        :param uuid_string: uuid string to compress to bytes
        :returns: a byte representation of the uuid

        """
        uuid_obj = uuid.UUID(uuid_string)
        return uuid_obj.bytes

    @classmethod
    def convert_uuid_bytes_to_hex(cls, uuid_byte_string):
        """Generate uuid.hex format based on byte string.

        :param uuid_byte_string: uuid string to generate from
        :returns: uuid hex formatted string

        """
        uuid_obj = uuid.UUID(bytes=uuid_byte_string)
        return uuid_obj.hex

    @classmethod
    def _convert_time_string_to_float(cls, time_string):
        """Convert a time formatted string to a float.

        :param time_string: time formatted string
        :returns: a timestamp as a float

        """
        time_object = timeutils.parse_isotime(time_string)
        return (timeutils.normalize_time(time_object) -
                datetime.datetime.utcfromtimestamp(0)).total_seconds()

    @classmethod
    def _convert_float_to_time_string(cls, time_float):
        """Convert a floating point timestamp to a string.

        :param time_float: integer representing timestamp
        :returns: a time formatted strings

        """
        time_object = datetime.datetime.utcfromtimestamp(time_float)
        return ks_utils.isotime(time_object, subsecond=True)

    @classmethod
    def attempt_convert_uuid_hex_to_bytes(cls, value):
        """Attempt to convert value to bytes or return value.

        :param value: value to attempt to convert to bytes
        :returns: tuple containing boolean indicating whether user_id was
                  stored as bytes and uuid value as bytes or the original value

        """
        try:
            return (True, cls.convert_uuid_hex_to_bytes(value))
        except (ValueError, TypeError):
            # ValueError: this might not be a UUID, depending on the
            # situation (i.e. federation)
            # TypeError: the provided value may be binary encoded
            # in which case just return the value (i.e. Python 3)
            return (False, value)

    @classmethod
    def base64_encode(cls, s):
        """Encode a URL-safe string.

        :type s: str
        :rtype: str

        """
        # urlsafe_b64encode() returns bytes so need to convert to
        # str, might as well do it before stripping.
        return base64.urlsafe_b64encode(s).decode('utf-8').rstrip('=')

    @classmethod
    def random_urlsafe_str_to_bytes(cls, s):
        """Convert string from :func:`random_urlsafe_str()` to bytes.

        :type s: str
        :rtype: bytes

        """
        # urlsafe_b64decode() requires str, unicode isn't accepted.
        s = str(s)

        # restore the padding (==) at the end of the string
        return base64.urlsafe_b64decode(s + '==')

    @classmethod
    def _convert_or_decode(cls, is_stored_as_bytes, value):
        """Convert a value to text type, translating uuid -> hex if required.

        :param is_stored_as_bytes: whether value is already bytes
        :type is_stored_as_bytes: boolean
        :param value: value to attempt to convert to bytes
        :type value: str or bytes
        :rtype: str
        """
        if is_stored_as_bytes:
            return cls.convert_uuid_bytes_to_hex(value)
        elif isinstance(value, bytes):
            return value.decode('utf-8')
        return value

    @classmethod
    def convert_integer_to_method_list(cls, intx):
        method = cls.default_method_list
        method_list = []
        for i in range(len(method)):
            if intx & (1 << i):
                method_list.append(method[i])
        return method_list
    
    @classmethod
    def convert_method_list_to_integer(cls, method_list):
        method = cls.default_method_list
        intx = 0
        for i in range(len(method)):
            if method[i] in method_list:
                intx |= (1 << i)
        return intx
    
        
class UnscopedPayload(BasePayload):
    version = 0

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        expires_at_str = cls._convert_float_to_time_string(payload[2])
        audit_ids = list(map(cls.base64_encode, payload[3]))
        system = None
        project_id = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        thumbprint = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id, thumbprint)


class DomainScopedPayload(BasePayload):
    version = 1

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        try:
            b_domain_id = cls.convert_uuid_hex_to_bytes(domain_id)
        except ValueError:
            # the default domain ID is configurable, and probably isn't a UUID
            #if domain_id == CONF.identity.default_domain_id:
            #    b_domain_id = domain_id
            #else:
            #    raise
            b_domain_id = domain_id
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, b_domain_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        try:
            domain_id = cls.convert_uuid_bytes_to_hex(payload[2])
        except ValueError:
            # the default domain ID is configurable, and probably isn't a UUID
            if isinstance(payload[2], bytes):
                payload[2] = payload[2].decode('utf-8')
            #if payload[2] == CONF.identity.default_domain_id:
            #    domain_id = payload[2]
            #else:
            #    raise
            domain_id = payload[2]
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        system = None
        project_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        thumbprint = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id, thumbprint)


class ProjectScopedPayload(BasePayload):
    version = 2

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, b_project_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        # from keystone.auth import plugins as auth_plugins
        # methods = auth_plugins.convert_integer_to_method_list(payload[1])
        methods = cls.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        system = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        thumbprint = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id, thumbprint)


class TrustScopedPayload(BasePayload):
    version = 3

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        b_trust_id = cls.convert_uuid_hex_to_bytes(trust_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))

        return (b_user_id, methods, b_project_id, expires_at_int, b_audit_ids,
                b_trust_id)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        trust_id = cls.convert_uuid_bytes_to_hex(payload[5])
        system = None
        domain_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        thumbprint = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id, thumbprint)


class FederatedUnscopedPayload(BasePayload):
    version = 4

    @classmethod
    def pack_group_id(cls, group_dict):
        return cls.attempt_convert_uuid_hex_to_bytes(group_dict['id'])

    @classmethod
    def unpack_group_id(cls, group_id_in_bytes):
        (is_stored_as_bytes, group_id) = group_id_in_bytes
        group_id = cls._convert_or_decode(is_stored_as_bytes, group_id)
        return {'id': group_id}

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        b_group_ids = list(map(cls.pack_group_id, federated_group_ids))
        b_idp_id = cls.attempt_convert_uuid_hex_to_bytes(identity_provider_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                               audit_ids))

        return (b_user_id, methods, b_group_ids, b_idp_id, protocol_id,
                expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        group_ids = list(map(cls.unpack_group_id, payload[2]))
        (is_stored_as_bytes, idp_id) = payload[3]
        idp_id = cls._convert_or_decode(is_stored_as_bytes, idp_id)
        protocol_id = payload[4]
        if isinstance(protocol_id, bytes):
            protocol_id = protocol_id.decode('utf-8')
        expires_at_str = cls._convert_float_to_time_string(payload[5])
        audit_ids = list(map(cls.base64_encode, payload[6]))
        system = None
        project_id = None
        domain_id = None
        trust_id = None
        access_token_id = None
        app_cred_id = None
        thumbprint = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, group_ids, idp_id,
                protocol_id, access_token_id, app_cred_id, thumbprint)


class FederatedScopedPayload(FederatedUnscopedPayload):
    version = None

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        b_scope_id = cls.attempt_convert_uuid_hex_to_bytes(
            project_id or domain_id)
        b_group_ids = list(map(cls.pack_group_id, federated_group_ids))
        b_idp_id = cls.attempt_convert_uuid_hex_to_bytes(identity_provider_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                               audit_ids))

        return (b_user_id, methods, b_scope_id, b_group_ids, b_idp_id,
                protocol_id, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, scope_id) = payload[2]
        scope_id = cls._convert_or_decode(is_stored_as_bytes, scope_id)
        project_id = (
            scope_id
            if cls.version == FederatedProjectScopedPayload.version else None)
        domain_id = (
            scope_id
            if cls.version == FederatedDomainScopedPayload.version else None)
        group_ids = list(map(cls.unpack_group_id, payload[3]))
        (is_stored_as_bytes, idp_id) = payload[4]
        idp_id = cls._convert_or_decode(is_stored_as_bytes, idp_id)
        protocol_id = payload[5]
        if isinstance(protocol_id, bytes):
            protocol_id = protocol_id.decode('utf-8')
        expires_at_str = cls._convert_float_to_time_string(payload[6])
        audit_ids = list(map(cls.base64_encode, payload[7]))
        system = None
        trust_id = None
        access_token_id = None
        app_cred_id = None
        thumbprint = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, group_ids, idp_id,
                protocol_id, access_token_id, app_cred_id, thumbprint)


class FederatedProjectScopedPayload(FederatedScopedPayload):
    version = 5


class FederatedDomainScopedPayload(FederatedScopedPayload):
    version = 6


class OauthScopedPayload(BasePayload):
    version = 7

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        b_access_token_id = cls.attempt_convert_uuid_hex_to_bytes(
            access_token_id)
        return (b_user_id, methods, b_project_id, b_access_token_id,
                expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        (is_stored_as_bytes, access_token_id) = payload[3]
        access_token_id = cls._convert_or_decode(is_stored_as_bytes,
                                                 access_token_id)
        expires_at_str = cls._convert_float_to_time_string(payload[4])
        audit_ids = list(map(cls.base64_encode, payload[5]))
        system = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        app_cred_id = None
        thumbprint = None

        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id, thumbprint)


class SystemScopedPayload(BasePayload):
    version = 8

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        return (b_user_id, methods, system, expires_at_int, b_audit_ids)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        system = payload[2]
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        project_id = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        thumbprint = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id, thumbprint)


class ApplicationCredentialScopedPayload(BasePayload):
    version = 9

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes,
                           audit_ids))
        b_app_cred_id = cls.attempt_convert_uuid_hex_to_bytes(app_cred_id)
        return (b_user_id, methods, b_project_id, expires_at_int, b_audit_ids,
                b_app_cred_id)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        expires_at_str = cls._convert_float_to_time_string(payload[3])
        audit_ids = list(map(cls.base64_encode, payload[4]))
        system = None
        domain_id = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        (is_stored_as_bytes, app_cred_id) = payload[5]
        app_cred_id = cls._convert_or_decode(is_stored_as_bytes, app_cred_id)
        thumbprint = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id, thumbprint)


class Oauth2CredentialsScopedPayload(BasePayload):
    version = 10

    @classmethod
    def assemble(cls, user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint):
        b_user_id = cls.attempt_convert_uuid_hex_to_bytes(user_id)
        methods = cls.convert_method_list_to_integer(methods)
        b_project_id = cls.attempt_convert_uuid_hex_to_bytes(project_id)
        b_domain_id = cls.attempt_convert_uuid_hex_to_bytes(domain_id)
        expires_at_int = cls._convert_time_string_to_float(expires_at)
        b_audit_ids = list(map(cls.random_urlsafe_str_to_bytes, audit_ids))
        b_thumbprint = (False, thumbprint)
        return (b_user_id, methods, b_project_id, b_domain_id, expires_at_int,
                b_audit_ids, b_thumbprint)

    @classmethod
    def disassemble(cls, payload):
        (is_stored_as_bytes, user_id) = payload[0]
        user_id = cls._convert_or_decode(is_stored_as_bytes, user_id)
        methods = cls.convert_integer_to_method_list(payload[1])
        (is_stored_as_bytes, project_id) = payload[2]
        project_id = cls._convert_or_decode(is_stored_as_bytes, project_id)
        (is_stored_as_bytes, domain_id) = payload[3]
        domain_id = cls._convert_or_decode(is_stored_as_bytes, domain_id)
        expires_at_str = cls._convert_float_to_time_string(payload[4])
        audit_ids = list(map(cls.base64_encode, payload[5]))
        (is_stored_as_bytes, thumbprint) = payload[6]
        thumbprint = cls._convert_or_decode(is_stored_as_bytes, thumbprint)
        system = None
        trust_id = None
        federated_group_ids = None
        identity_provider_id = None
        protocol_id = None
        access_token_id = None
        app_cred_id = None
        return (user_id, methods, system, project_id, domain_id,
                expires_at_str, audit_ids, trust_id, federated_group_ids,
                identity_provider_id, protocol_id, access_token_id,
                app_cred_id, thumbprint)


_PAYLOAD_CLASSES = [
    UnscopedPayload,
    DomainScopedPayload,
    ProjectScopedPayload,
    TrustScopedPayload,
    FederatedUnscopedPayload,
    FederatedProjectScopedPayload,
    FederatedDomainScopedPayload,
    OauthScopedPayload,
    SystemScopedPayload,
    ApplicationCredentialScopedPayload,
    Oauth2CredentialsScopedPayload,
]