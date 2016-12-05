class Protocol(object):
    """
    Message sturcture:
        * ENCRYPT: username||pdw||token||token_len
        * DECRYPT: username||pdw||token||token_len
        * PWD_LOGIN: username||pwd
        
        * DECRYPTION_ERR: file_path||msg||msg_len
        * NEW_TOKEN: token

    Messages which format has not been sepecified above do not carry any data,
    consisting only of the byte tag defined below.

    Mesasges that send a token have a fixed 3-byte at the end of the message
    (token_len), which is the length of the token. NOTE: THIS ASSUMES THAT 
    THE TOKEN HAS A MAXIMUM LENGTH OF 999. An alternative would be to add
    separators, but that could cause issues if the delimiter appeared somewhere
    else.

    After receiving PWD_LOGIN, the server replies with a token (i.e.
    sends NEW_TOKEN message). The client app has to update the token it has
    stored locally.
    """

    # messages client->server
    ENCRYPT = b'enc'  # NOTE: client doens't have to send this directly
    DECRYPT = b'dec'
    PWD_LOGIN = b'log'

    # messages server->client
    PWD_LOGIN_ERR = b'log_err'
    # generic error for all token error msgs: we don't want to leak any info 
    # to potential attackers
    TOKEN_WRONG_ERR = b'tok_wrong_err'
    DECRYPTION_ERR = b'dec_err'  # error in a decryption of a file
    NEW_TOKEN = b'tok_new'  # commands the client to update the token
    NO_USER_ERR = b'nu_err'

    # internal messages
    ENCRYPT_INTERNAL = b'int_enc'