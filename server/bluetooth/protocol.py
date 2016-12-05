class Protocol(object):
    """
    Message sturcture:
        * ENCRYPT: username||pdw||token
        * DECRYPT: username||pdw||token
        * PWD_LOGIN: username||pwd
        
        * DECRYPTION_ERR: file_path||msg
        * NEW_TOKEN: token

    Messages which format has not been sepecified above do not carry any data,
    consisting only of the byte tag defined below.

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
    TOKEN_EXPIRED_ERR = b'tok_exp_err'
    TOKEN_WRONG_ERR = b'tok_wrong_err'
    DECRYPTION_ERR = b'dec_err'  # error in a decryption of a file
    NEW_TOKEN = b'tok_new'  # commands the client to update the token
    NO_USER_ERR = b'nu_err'