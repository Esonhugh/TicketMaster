from cryptography.fernet import Fernet
from cryptography import fernet
# from keystone.token.token_formatters import _PAYLOAD_CLASSES
from payload import _PAYLOAD_CLASSES
import json
import msgpack

_default_keys = [
    b"qQ4gwksmLTGjceVO4WZ_wiLitKpOYuRJv-NksBclq5w="
    b"d3srWp1fOS4saKURhL91rgFvJdI90DpfXcnKH_3uWxQ="
]

_test_passwords = [
    "gAAAAABll8P3YdzVMbp-oXOVQcdx3z6_5Szk2I1y7gZmcBs9EoGnSSjiQqScpjhSE9MHpyZzsIvPX33mQIEw1ZgPznD0BK43SdtETl7JlRkMjjuYHxBXVQ54mAwAFSAj8QPSHMTRldsHxYUdC2w6HmPBeEZsRmCxDvCUL-_Vm_Zik_yYZ0VF4oY",
    "gAAAAABll4fW_l41sb5Ye9s2voeImGVn4d7U3yUXvVib57p8LXwUDAVV6MT8jjZtYvJz6NxkXJBWF8CXmnzwt6ZVw90yj7ydQnff9Mk6Sww72swOJh7joXz1ALpzT80i9LfFAbXYtm19u1A4zhazWzsomNHfn9t-uoGRsopukLx-B-knXLTWD00",
    "gAAAAABll4duerSNyJLBRNTLHhT8JLiyLKQlAVjBB0jpMgmuT-zpdfXFxG__7zR8sVHTkF6eB10JcTMBmRt7gfY229DgfUHjAG7LNFcQ-XDXgEty5UDUxteFj2meqtzAIra2DvQXhYu6ZUe99d904v6OMYsBGJN4x6H8tksQN0MmJhjBvcIwzKo",
    "gAAAAABll4dkOYHNN4WqRS_UDkaLCJMjIWQlqOasmG8ikyjG_ZaDYAGzPLiHqXnrpQ2eHoWsTP1jHrSyCSSemveYN8TFleT1FAX__v00VUOI0r0DDBlBTqcor1Wh-V4S6WX41rNfc8hGvDqwMt30mxOXReb7F5AzfZC5C7K3NNrUZmF4FEHH20Q",
]

def generate_multi_key(keys):
    return fernet.MultiFernet(Fernet(key) for key in keys)

def restore_padding(token):
    """Restore padding based on token size.

    :param token: token to restore padding on
    :type token: str
    :returns: token with correct padding

    """
    # Re-inflate the padding
    mod_returned = len(token) % 4
    if mod_returned:
        missing_padding = 4 - mod_returned
        token += '=' * missing_padding
    return token

def random_urlsafe_str():
    """Generate a random URL-safe string.

    :rtype: str
    """
    # chop the padding (==) off the end of the encoding to save space
    return base64.urlsafe_b64encode(uuid.uuid4().bytes)[:-2].decode('utf-8')
    
def audit_id_gen():
    return random_urlsafe_str()

def decrypt_and_disassemble(keys,token):
    multi_keys = generate_multi_key(keys)
    raw_data = multi_keys.decrypt(restore_padding(token))
    serialized_payload = raw_data
    try:
        versioned_payload = msgpack.unpackb(serialized_payload)
        # print(versioned_payload)
    except UnicodeDecodeError:
        versioned_payload = msgpack.unpackb(serialized_payload, raw=True)
    except Exception as e:
        print(e)
        raise "msgpack.unpackb error"

    version, payload = versioned_payload[0], versioned_payload[1:]

    try:
        if _PAYLOAD_CLASSES[version].version == version:
            # print("Version:" + str(version))
            (user_id, methods, system, project_id, domain_id,
                 expires_at, audit_ids, trust_id, federated_group_ids,
                 identity_provider_id, protocol_id, access_token_id,
                 app_cred_id, thumbprint) = (
                    _PAYLOAD_CLASSES[version].disassemble(payload)) 
        else:
            for payload_class in _PAYLOAD_CLASSES:
                if version == payload_class.version:
                    (user_id, methods, system, project_id, domain_id,
                    expires_at, audit_ids, trust_id, federated_group_ids,
                    identity_provider_id, protocol_id, access_token_id,
                    app_cred_id, thumbprint) = (
                        payload_class.disassemble(payload))
                    
        return (user_id, methods, system, project_id, domain_id,
                    expires_at, audit_ids, trust_id, federated_group_ids,
                    identity_provider_id, protocol_id, access_token_id,
                    app_cred_id, thumbprint) 
    except Exception as e:
        print(e)
        raise "disassemble error"

def decrypt_and_disassemble_json(keys,token):
    (user_id, methods, system, project_id, domain_id,
        expires_at, audit_ids, trust_id, federated_group_ids,
        identity_provider_id, protocol_id, access_token_id,
        app_cred_id, thumbprint) = decrypt_and_disassemble(keys, token)
    json_dict = {
            "user_id": user_id,
            "methods": methods,
            "system": system,
            "project_id": project_id,
            "domain_id": domain_id,
            "expires_at": expires_at,
            "audit_ids": audit_ids,
            "trust_id": trust_id,
            "federated_group_ids": federated_group_ids,
            "identity_provider_id": identity_provider_id,
            "protocol_id": protocol_id,
            "access_token_id": access_token_id,
            "app_cred_id": app_cred_id,
            "thumbprint": thumbprint
        }
    
    return json_dict

def main():
    for password in _test_passwords:
        json_dic = decrypt_and_disassemble_json(_default_keys,password)
        print(json.dumps(json_dic, indent=4))

if __name__ == "__main__":
    main()